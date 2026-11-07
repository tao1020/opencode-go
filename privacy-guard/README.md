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
