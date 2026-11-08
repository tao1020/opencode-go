package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestMySQLCommandCredentials(t *testing.T) {
	for _, cmd := range []string{`mysql -h db -u alice -pSecret123`, `mysql --user=alice --password=Secret123`, `sudo /usr/bin/mysql -ualice -p'Secret123'`, `mysql -u "alice" -p"Secret123"`, "mysql -u alice \\\n -pSecret123", `执行 mysql -u alice -pSecret123 登录数据库`} {
		t.Run(cmd, func(t *testing.T) {
			g, e := NewGateway(Config{ClientAPIKey: testClientKey, Detector: "credentials"})
			if e != nil {
				t.Fatal(e)
			}
			input := map[string]any{"content": cmd}
			_, r := postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, input), testClientKey)
			for _, v := range []string{"alice", "Secret123"} {
				if strings.Contains(string(r.Payload), v) {
					t.Fatalf("credential leaked %q", v)
				}
			}
			if !reflect.DeepEqual(input, restoreTree(mustDecode(t, r.Payload), r.Mappings)) {
				t.Fatal("round trip failed")
			}
		})
	}
}
func TestMySQLArgumentBoundaries(t *testing.T) {
	for _, cmd := range []string{`mysql -p database`, `mysql --password database`, `mysql -P3306; other -p8080`, `other -p8080`, `mysql -u "$DB_USER" -p"$DB_PASSWORD"`, `mysql -- -pNotAnOption`} {
		if spans := commandCredentialSpans(cmd); len(spans) != 0 {
			t.Fatalf("unexpected credential in %q: %v", cmd, spans)
		}
	}
	spans := commandCredentialSpans(`mysql -u 'alice user' -p'has spaces'`)
	if len(spans) != 2 {
		t.Fatal("quoted values lost")
	}
}

func TestRegistryLoginCredentials(t *testing.T) {
	for _, cmd := range []string{
		`docker login registry.example --username 1234567890123 --password eyJfake.synthetic.signature`,
		`modctl login registry.example --username=1234567890123 --password=eyJfake.synthetic.signature`,
		`clawhub login --registry https://registry.example --token clh_SyntheticToken123456`,
		`docker login registry.example -u 'alice user' -p 'short password'`,
	} {
		t.Run(cmd, func(t *testing.T) {
			g, e := NewGateway(Config{ClientAPIKey: testClientKey, Detector: "credentials"})
			if e != nil {
				t.Fatal(e)
			}
			input := map[string]any{"content": cmd}
			_, r := postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, input), testClientKey)
			if len(r.Mappings) == 0 {
				t.Fatal("login credentials not detected")
			}
			for _, value := range []string{"1234567890123", "eyJfake.synthetic.signature", "clh_SyntheticToken123456", "alice user", "short password"} {
				if strings.Contains(string(r.Payload), value) {
					t.Fatal("credential remained visible")
				}
			}
			if !reflect.DeepEqual(input, restoreTree(mustDecode(t, r.Payload), r.Mappings)) {
				t.Fatal("round trip failed")
			}
		})
	}
	for _, cmd := range []string{`docker pull image:tag`, `docker login --password-stdin`, `clawhub login --token "$TOKEN"`, `docker login --username alice; curl -p 8080`} {
		spans := commandCredentialSpans(cmd)
		for _, span := range spans {
			if strings.Contains(cmd[span.start:span.end], "8080") || strings.Contains(cmd[span.start:span.end], "$TOKEN") {
				t.Fatal("other command or reference altered")
			}
		}
	}
}

func TestCommandNameAsCredentialValue(t *testing.T) {
	text := `docker login registry.example --username mysql --password docker`
	spans := commandCredentialSpans(text)
	if len(spans) != 2 || text[spans[0].start:spans[0].end] != "mysql" || text[spans[1].start:spans[1].end] != "docker" {
		t.Fatal("credential value parsed as a new command")
	}
}

func TestCommandWordsInRegistryAndContinuation(t *testing.T) {
	for _, text := range []string{`docker login mysql --username alice --password short`, `mysql -u \
 alice -pSecret123`} {
		if len(commandCredentialSpans(text)) != 2 {
			t.Fatal("argument consumed as command or continuation")
		}
	}
}
