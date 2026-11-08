"""Real OpenCode CLI + real guard + fake upstream, synthetic secrets only."""
import http.server
import json
import os
import re
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

binary = str(Path(sys.argv[1]).resolve(strict=True))
opencode = os.environ.get('OPENCODE_BINARY') or shutil.which('opencode') or str(Path.home() / '.local/bin/opencode')
opencode = str(Path(opencode).resolve(strict=True))
root = Path(tempfile.mkdtemp(prefix='privacy-dev-flow-'))
fixture = root / 'settings.env'
secret = 'DevFlowSyntheticSecret9!OnlyTest'
prompt_secret = 'PromptSyntheticSecret8!OnlyTest'
extra_credentials = ('alice_synthetic', 'LTAIabcdefghijklmnop', 'SyntheticSecretAccessKey123!')
extra_config = f'DB_USERNAME="{extra_credentials[0]}"\nACCESS_KEY_ID="{extra_credentials[1]}"\nSECRET_ACCESS_KEY="{extra_credentials[2]}"\n'
fixture.write_text(f'DB_PASSWORD="{secret}"\nPORT=8000\n'+extra_config)
fixture.chmod(0o600)
observations = []
session_scopes = set()
failures = []
completed = threading.Event()

class FakeModel(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        return
    def do_POST(self):
        try:
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            if any(value.encode() in raw for value in (secret, prompt_secret, *extra_credentials)):
                failures.append('raw file or CLI-prompt secret reached fake upstream')
            body = json.loads(raw)
            is_development = any(t.get('function',{}).get('name') == 'read' for t in body.get('tools', []))
            observations.append({'model':body.get('model'), 'reasoning':body.get('reasoning_effort'), 'session_header':bool(self.headers.get('x-opencode-session')), 'kind':'development' if is_development else 'auxiliary'})
            tool_fields={t['function']['name']:list(t['function'].get('parameters',{}).get('properties',{})) for t in body.get('tools',[]) if t['function']['name'] in ['read','edit']}
            observations[-1]['tool_fields']=tool_fields
            if is_development:
                session_scopes.add(self.headers.get('x-opencode-session'))
            step = sum(item['kind']=='development' for item in observations) if is_development else 0
            if not is_development:
                name, arguments = None, None
            elif step == 1:
                name, arguments = 'read', {('path' if 'path' in tool_fields.get('read',[]) else 'filePath'):str(fixture)}
            elif step == 2:
                # Inspect decoded message strings only. Never print their content.
                texts = []
                def collect(v):
                    if isinstance(v, str):
                        texts.append(v)
                    elif isinstance(v, dict):
                        for item in v.values():
                            collect(item)
                    elif isinstance(v, list):
                        for item in v:
                            collect(item)
                collect(body.get('messages', []))
                match = re.search(r'DB_PASSWORD="(__PG_[a-f0-9]{32}__)"', '\n'.join(texts))
                if not match:
                    raise ValueError('masked configuration token not found')
                token = match.group(1)
                name, arguments = 'edit', {('path' if 'path' in tool_fields.get('edit',[]) else 'filePath'):str(fixture), 'oldString':f'DB_PASSWORD="{token}"', 'newString':f'DB_PASSWORD="{token}"\nFEATURE_ENABLED=true'}
            else:
                name, arguments = None, None
                completed.set()
            self.send_response(200)
            self.send_header('Content-Type','text/event-stream')
            self.end_headers()
            def emit(delta, finish=None):
                event={'id':f'chatcmpl-dev-flow-{step}','object':'chat.completion.chunk','created':1,'model':'deepseek-v4.1-flash','choices':[{'index':0,'delta':delta,'finish_reason':finish}]}
                self.wfile.write(('data: '+json.dumps(event)+'\n\n').encode())
                self.wfile.flush()
            if name:
                emit({'role':'assistant','tool_calls':[{'index':0,'id':f'call_dev_{step}','type':'function','function':{'name':name,'arguments':''}}]})
                encoded=json.dumps(arguments)
                # Deliberately split the placeholder and escaped JSON across events.
                for i in range(0,len(encoded),7):
                    emit({'tool_calls':[{'index':0,'function':{'arguments':encoded[i:i+7]}}]})
                emit({},'tool_calls')
            else:
                emit({'role':'assistant','content':'Done.'})
                emit({},'stop')
            self.wfile.write(b'data: [DONE]\n\n')
            self.wfile.flush()
        except Exception as exc:
            failures.append(type(exc).__name__ + ': fake upstream scenario failed')
            try:
                self.send_error(500,'test scenario failed')
            except OSError:
                pass

server=http.server.ThreadingHTTPServer(('127.0.0.1',0),FakeModel)
threading.Thread(target=server.serve_forever,daemon=True).start()
with socket.socket() as reservation:
    reservation.bind(('127.0.0.1',0))
    port=reservation.getsockname()[1]
client_key='dev-flow-client-synthetic-key'
client_key_file=root/'client.key'
upstream_key_file=root/'upstream.key'
for path, value in [(client_key_file,client_key),(upstream_key_file,'dev-flow-upstream-synthetic-key')]:
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as target:
        target.write(value+'\n')
env=dict(os.environ,GUARD_DETECTOR=os.environ.get('GUARD_DETECTOR','credentials'),GUARD_LISTEN=f'127.0.0.1:{port}',GUARD_REVERSIBLE='true',UPSTREAM_URL=f'http://127.0.0.1:{server.server_port}/v1/chat/completions',UPSTREAM_API_KEY_FILE=str(upstream_key_file),CLIENT_API_KEY_FILE=str(client_key_file))
env.pop('CLIENT_API_KEY',None)
env.pop('UPSTREAM_API_KEY',None)
log=(root/'guard.log').open('wb')
guard=subprocess.Popen([binary],env=env,stdout=log,stderr=log,start_new_session=True)
cli=None
try:
    deadline=time.monotonic()+10
    while True:
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz',timeout=1) as r:
                health=json.load(r)
            break
        except OSError:
            if guard.poll() is not None or time.monotonic()>deadline:
                raise RuntimeError('guard startup failed')
            threading.Event().wait(0.05)
    run_help=subprocess.run([opencode,'run','--help'],capture_output=True,text=True,timeout=15)
    standalone=['--standalone'] if '--standalone' in run_help.stdout else []
    provider_id='privacy-go' if standalone else 'opencode-go'
    provider_model=provider_id+'/deepseek-v4.1-flash'
    variant_args=[] if standalone else ['--variant','high']
    override = {
        'enabled_providers': [provider_id],
        'model': provider_model,
        'agent': {
            'build': {'model':provider_model,'variant':'high'},
            'title': {'model':provider_model},
        },
        'provider': {provider_id: {'npm':'@ai-sdk/openai-compatible','name':'Local credential guard','models': {'deepseek-v4.1-flash': {'name':'DeepSeek Flash local', 'reasoning':True,'limit':{'context':262144,'output':65536},'variants':{'high':{'reasoningEffort':'high'}}}},'options': {
            'baseURL':f'http://127.0.0.1:{port}/v1',
            'apiKey':'{file:'+str(client_key_file)+'}',
        }}},
        'permission': {
            'external_directory':{str(root)+'/*':'allow'},
            'read':{str(fixture):'allow',str(fixture).lstrip('/'):'allow'},
            'edit':{str(fixture):'allow',str(fixture).lstrip('/'):'allow'},
        },
    }
    if not standalone:
        override['provider'][provider_id]={'options':override['provider'][provider_id]['options']}
    cli_env=dict(os.environ,OPENCODE_CONFIG_CONTENT=json.dumps(override))
    cli=subprocess.Popen([opencode,'run',*standalone,'--model',(provider_model+'#high' if standalone else provider_model),*variant_args,f'Read {fixture} then add FEATURE_ENABLED=true without changing DB_PASSWORD. Use read and edit tools. Synthetic transport fixture: password="{prompt_secret}". Do not write this fixture value.'],cwd=root,env=cli_env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:
        out,err=cli.communicate(timeout=90)
    except subprocess.TimeoutExpired:
        failures.append('OpenCode CLI timeout')
        os.killpg(cli.pid,signal.SIGKILL)
        out,err=cli.communicate()
    if cli.returncode != 0:
        failures.append('OpenCode CLI failed')
    expected=f'DB_PASSWORD="{secret}"\nFEATURE_ENABLED=true\nPORT=8000\n'+extra_config
    if fixture.read_text()!=expected:
        failures.append('edited file does not preserve exact original password and new setting')
    if not completed.is_set():
        failures.append('read/edit/final response cycle not completed')
    development = [x for x in observations if x['kind']=='development']
    if len(development)<3 or not all(x['model']=='deepseek-v4.1-flash' and x['reasoning']=='high' and x['session_header'] for x in development):
        failures.append('Go/high/session headers not preserved')
    if len(session_scopes) != 1:
        failures.append('OpenCode session scope changed between requests')
    log.flush()
    if any(value in (root/'guard.log').read_text() for value in (secret, prompt_secret, *extra_credentials)):
        failures.append('guard log contains synthetic secret')
    diagnostic = (out + err).decode('utf-8', errors='replace').replace(secret, '<synthetic-secret>').replace(prompt_secret, '<synthetic-prompt-secret>')[:3000] if failures else ''
    print(json.dumps({'passed':not failures,'requests':len(observations),'observations':observations,'failures':failures,'fixture_directory':str(root),'cli_output_bytes':len(out)+len(err),'diagnostic':diagnostic},indent=2))
finally:
    if cli is not None and cli.poll() is None:
        os.killpg(cli.pid,signal.SIGKILL)
        cli.wait()
    if guard.poll() is None:
        os.killpg(guard.pid,signal.SIGTERM)
        try:
            guard.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(guard.pid,signal.SIGKILL)
            guard.wait()
    log.close()
    server.shutdown()
    server.server_close()
if failures:
    raise SystemExit(1)
