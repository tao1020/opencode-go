# privacy-guard

OpenCode Go 的本地隐私网关。请求发往模型 provider 之前遮盖密钥，响应回到本机之后还原。只处理模型上行的文本。

## 适用范围

本次启用范围是 OpenCode Go 的 `deepseek-v4.1-flash`，保留当前开发任务的 high 推理设置。辅助标题请求可以沿用 low。其他模型和协议没有完成验收，不宣称受保护。

保护范围是发给模型的文本，不是所有网络出口。

- 在请求发给 provider 前，把识别出的文本秘密换成占位符；不保证识别所有秘密或编码后的内容。
- Coder 由本服务还原响应；Mac 由 Go 插件还原响应，本服务仅负责本地替换。
- 本地工具的参数会完整还原。`gh`、`curl` 这类工具仍可能把值发到外部服务，这一层不拦。
- 不做语义级判断。检测按词法规则匹配，无法证明某段文本“语义上不是密钥”。

## 两种运行方式

### Coder：可逆代理

必须设置 `GUARD_REVERSIBLE=true`。不设置时转发的是单向脱敏结果，原文无法还原。可逆代理只接受 `deepseek-v4.1-flash`；其他模型返回明确错误，不会自动切换或绕过保护。

### Mac：只扫描

不设置 `UPSTREAM_URL` 时，进程提供本地 `/mask`、`/inspect` 和 `/healthz`，不向外转发。chat 路由返回 404。

## 失败时的行为

- 替换失败：返回错误，不直连 provider。容量或服务故障返回 503，无效输入返回 400 或 413。没有“脱敏失败就原样转发”的分支。
- 还原失败：JSON 响应返回 502；SSE 直接断开连接，不发送正常的流结束标记。

## 接口

### POST /mask

```json
{"version":1,"scope":"<32 到 128 个字符>","payload":{}}
```

```json
{"version":1,"payload":{},"mappings":[{"token":"__PG_<32 位十六进制>__","original":"...","originalType":"number"}],"uninspectedMedia":false}
```

`originalType` 只在原值是 JSON 数字时出现。`scope` 由调用方提供，同一 scope 内同一取值得到同一 token。

### 其他路由

`/inspect` 是早期检查接口，仍需本地客户端鉴权，但本方案不调用它。单向 chat 模式只留作实验，部署示例不使用；Coder 必须开启可逆模式。

## 排除与限制

支持 OpenCode CLI 额外 JSON 引号中的密码赋值、鉴权值和环境变量默认值。替换只改秘密所在的原始字节，不重写整段文本；这不等于支持任意编码。

`string`、`example` 等占位词和协议用词，只在明确的凭据位置替换，不向其他字段扩散。若真实密码恰好等于这些词，其他位置的同名裸值仍可能发给模型。JSON 转义中的短值也只替换原位置。

工具定义中的必填属性名保持不变，避免改坏工具调用。说明、默认值和枚举仍参与替换，其中的普通文本可能因为与秘密同名而误判。

- 标准环境变量引用不脱敏：`os.environ["X"]`、`os.getenv("X")`、`os.Getenv("X")`、`process.env.X`。Shell 形式只豁免大写变量名，如 `${TOKEN}`、`$TOKEN`；小写 `${dbPassword}` 按值处理。
- 其他语言或框架的引用写法可能被当成值。未知写法按值处理，不会被静默忽略。
- `os.getenv("X", "default")` 的默认值是字面量，仍会脱敏。
- 图片、音频等媒体不改动，响应里 `uninspectedMedia` 为 `true`。
- 数字保留类型，映射带 `originalType`。
- 只支持 OpenAI Chat Completions 形状。Responses、Anthropic 不在范围内。

## 凭据与内存

- 客户端 key 和上游 key 都用文件：绝对路径、普通文件、非符号链接、权限 600。
- 进程不把 key、token 或原文写进日志。
- vault 只在内存，不落盘。TTL 1 小时；全局 8 MiB、单 scope 4 MiB、单 scope 2 万条映射。

## 部署示例

见 `deploy/`。

- `coder-privacy-guard.service`：systemd，专用无登录非 root 账号、600 权限的文件凭据和只读沙箱；不依赖 Coder 容器中不可用的动态用户凭据挂载。
- `mac-privacy-guard.plist`：launchd，占位符 `__HOME__`，只做扫描和 `/mask`，不配上游。

不要复用旧的扫描模板。那份模板用 `IPAddressAllow` 只允许本机回环，Coder 代理需要出站访问 provider，会连不上。

## 构建与检查

需要 Go 1.24.11 或更高版本。官方下载地址是 https://go.dev/dl/ 。

```sh
gofmt -l .
go vet ./...
go test -race ./...
```

## 许可证

本项目使用 MIT 许可证，见 LICENSE。依赖 gitleaks v8.30.1，MIT 许可证。没有复制或内联任何外部项目源码。

## 轻量凭据模式

设置 `GUARD_DETECTOR=credentials` 后，服务使用本地正则识别凭据，覆盖明确字段中的 AK/SK、密码和用户名、连接串中的用户名与密码、认证头，以及部分有固定格式的云访问密钥和私钥。`user`、`username`、`login` 等字段中的值会被处理，协议中的 `role: user` 保持有效。任意裸用户名、无格式且无上下文的 SK、图片和编码内容可能无法识别。

该模式不加载 Gitleaks 检测器和 NLP 模型。可执行文件仍包含旧模式的依赖，便于已有调用方继续使用。未设置 `GUARD_DETECTOR` 时，服务沿用原 Gitleaks 模式；`gitleaks` 也可显式选择。未知值会阻止启动。

轻量模式缓存文本摘要和检测位置，最多保存 1024 条记录和 65536 个位置。缓存达到上限时清空并重新检测。秘密集合和全局替换每次重新计算，因此后续消息揭示旧文本中的密码时，旧文本仍会得到遮盖。

同一客户端 key、会话 scope 和原值会得到相同 token。Harness 使用客户端 key 和会话 ID 派生稳定 scope。重启后重发包含原始值的历史，可以重建同样的替代值；只有旧 token 而没有原值的历史仍只能恢复为 token 字面量。更换 key 或会话会更换替代值。映射只保存在内存中。

这是凭据保护模式。人名、地址和普通业务内容不作为独立的识别类别。新识别出的凭据在旧历史中出现时仍会触发替换，因此服务无法保证上游缓存始终命中。

### DeepSeek Harness

Mac 和 Linux 都可以将服务作为本地 `/mask` 组件运行。设置 `GUARD_DETECTOR=credentials`，通过 `CLIENT_API_KEY_FILE` 指定本地 key。插件配置 `privacyEnabled=true`、`privacyEndpoint` 和 `privacyKeyFile`。关闭时先设置 `privacyEnabled=false`，重新加载客户端配置后再停止服务。

### OpenCode 官方 CLI

CLI 使用本地可逆代理。在 Mac 或 Linux 上设置 `GUARD_DETECTOR=credentials`、`GUARD_REVERSIBLE=true`、`CLIENT_API_KEY_FILE`、`UPSTREAM_API_KEY_FILE` 和 `UPSTREAM_URL`。上游 URL 指向当前 Go Chat Completions 接口。本机 OpenCode 2.0.24 使用下面的独立 `privacy-go` provider，配置回环地址和本地客户端 key。该方式可以避免内置 Go 登录凭据覆盖本地 key。

```json
{
  "provider": {
    "privacy-go": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Local credential guard",
      "models": {
        "deepseek-v4.1-flash": {
          "name": "DeepSeek Flash local",
          "reasoning": true,
          "limit": {"context": 262144, "output": 65536},
          "variants": {"high": {"reasoningEffort": "high"}}
        }
      },
      "options": {
        "baseURL": "http://127.0.0.1:8788/v1",
        "apiKey": "{file:/absolute/path/client.key}"
      }
    }
  }
}
```

Coder 的 OpenCode 1.16.2 使用原生 `opencode-go` provider，只覆盖其 `options.baseURL` 和 `options.apiKey`。该版本通过原生 provider 保留会话标识，运行时使用 `--model opencode-go/deepseek-v4.1-flash --variant high`。测试脚本按 CLI 是否支持 `--standalone` 选择这两种已验证的接入方式。

以上片段应合并到已有配置。使用 `opencode run -m privacy-go/deepseek-v4.1-flash#high` 调用本地保护路径。模型容量示例应与实际订阅模型声明一致。停用时切回原 `opencode-go/deepseek-v4.1-flash`，再停止本地代理。Harness 插件还原与代理还原分别对应两种接入方式，一条请求只需选择一种方式。当前验收模型仍为 `deepseek-v4.1-flash`，接口为 OpenAI Chat Completions。

部署模板已选择轻量模式。Mac 使用 launchd，Coder/Linux 使用 systemd，普通用户也可以直接启动二进制。所有模式均绑定回环地址。

### 本地验收

在 `privacy-guard` 目录运行以下命令。

```sh
go vet ./...
go test -race ./...
go test -run '^$' -bench BenchmarkCredentialLongHistory -benchtime=5x
go build -o /tmp/privacy-guard-preview .
```

在仓库根目录运行真实 daemon 联调。

```sh
GUARD_DETECTOR=credentials PRIVACY_GUARD_TEST_BINARY=/tmp/privacy-guard-preview npm test -- tests/privacy-daemon.integration.spec.ts
GUARD_DETECTOR=credentials python3 privacy-guard/integration/opencode_developer_flow.py /tmp/privacy-guard-preview
```

Python 命令使用已有虚拟环境执行。OpenCode 验收使用真实 CLI、本地模拟模型和合成凭据，检查读取配置、编辑文件、上游遮盖与本地还原。基准测试使用合成历史，其结果不代表真实模型的网络延迟或生成速度。

### 裸凭据补充规则

轻量模式还会检查消息正文中独占一行的裸值，包括工具输出。候选长度为 20–128 个字符，只允许 ASCII 字母、数字和下划线，至少包含两个大写字母、两个小写字母、两个数字，并且至少一个数字出现在最后四个字符之前。字符分布的 Shannon 熵须达到 3.5 bit/字符。已有凭据字段和固定格式规则仍独立生效。

这条补充规则只从消息正文发现候选，工具名称、schema 和协议字段不作为裸值扫描。识别后沿用现有全局遮盖与本地还原流程。纯十六进制、小写与数字组合、短值，以及埋在普通句子里的未知值可能漏检。独占一行的高随机性非秘密 ID 也可能被遮盖。

测试包含 500 个固定种子生成的随机字符串和 1000 个生成的普通标识符。这些样本用于回归检查，不能证明真实业务误判率低于 3%，也不能证明泄露率低于 5%。

### 登录命令中的凭据

轻量模式按参数位置识别 `mysql`、`mysqldump`、`mariadb` 的 `-u`、`--user`、`-p密码` 和 `--password=密码`，支持常见引号和反斜线续行。MySQL 的单独 `-p` 表示交互输入密码，其后空格分隔的数据库名保持原样。

`docker login`、`modctl login`、`clawhub login` 中的 `--username`、`--password`、`--token` 及常见 `-u`、`-p` 参数也会遮盖，支持空格或等号分隔的长参数。这些明确凭据位置不受裸值的长度和独占一行限制。命令、域名、端口和参数标志保留，凭据原值在响应返回本地后还原。

识别器只做字节位置分析，覆盖上述常见写法。它不执行命令，也不求值变量、命令替换、管道输入或任意 shell 脚本。环境变量引用沿用既有处理方式。

### 云控制台复制的 STS 凭据

腾讯云的 `TENCENTCLOUD_SECRET_ID`、`TENCENTCLOUD_SECRET_KEY`、`TENCENTCLOUD_SECURITY_TOKEN` 赋值沿用字段识别规则。控制台复制文本中的 `AccessKey ID`、`AccessKey Secret`、`SecurityToken`、`Secret ID`、`Secret Key` 标题也可与下一行值配对，支持标题的 Markdown 加粗、空白行和值后的“复制”标记。

这些明确字段中的完整值会被遮盖，支持点、连字符、下划线、斜线、加号和等号。长 SecurityToken 不受裸值规则的 128 位上限限制，仍受整个请求的大小限制。标题和“复制”标记保留，返回本地时原文逐字还原。
