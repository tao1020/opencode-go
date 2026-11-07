# Deploy examples

Two examples, different jobs.

- `coder-privacy-guard.service`: Coder 上的可逆代理。需要出站访问 provider。
- `mac-privacy-guard.plist`: Mac 上的本地扫描。没有上游，插件使用本地 `/mask` 接口。

两份示例都不启用单向 chat 路由。

## 生成 key

只为本地客户端生成随机 key：

```sh
umask 077
openssl rand -hex 32 > client.key
```

Coder 的 `upstream.key` 必须保存已有的 **OpenCode Go 订阅 API key**，不能随机生成。通过本地安全文件操作复制凭据，不要把值写进命令参数、日志或 Git。Mac 扫描服务不需要这个文件。

文件必须是普通文件，不能是符号链接。部署时设为 600；程序也接受 400 的只读文件。程序启动时检查文件访问权限，不依赖 systemd 创建凭据副本。

## Coder：systemd

1. 把二进制放到 `/usr/local/bin/privacy-guard`。
2. 创建专用、无登录权限的系统账号 `opencode-privacy`，不要复用已有业务账号。把两个 key 放到 `/etc/opencode-go-privacy/`；目录与文件都归此账号，目录权限 700，文件权限 600。当前 Coder 的 Loop/OpenCode 使用 root，能读取本地 client key。非 root CLI 不能直接照搬，需另行配置只允许该 CLI 用户读取的客户端凭据。
3. 确认 `UPSTREAM_URL` 指向 unit 中的 OpenCode Go 订阅端点，不要改成按量收费的 Zen 端点。
4. 安装 unit:

```sh
sudo cp coder-privacy-guard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now coder-privacy-guard
```

unit 使用专用非 root 账号、空 capability 集合和只读文件系统；环境变量里只有文件路径，没有凭据值。`ProtectSystem=strict` 让目录中的 key 在服务沙箱内不可写，不要去掉这个限制。保留此系统账号的 UID；若重建账号导致 UID 改变，必须重新设置文件属主。

这个 Coder 容器实测存在 `DynamicUser` 无法读取 `LoadCredential` 挂载目录的问题，因此这里不依赖该机制。不要通过 root 运行服务或放宽文件到组/其他用户可读来绕过检查。

旧模板里的 `IPAddressAllow=127.0.0.1/32` 只允许回环。Coder 代理要连 provider，套用那份限制会导致连接失败。

## Mac：launchd

把编译后的二进制放到 `~/.local/lib/privacy-guard/bin/privacy-guard`。本地 key 放到 `~/.local/state/privacy-guard/client-key`，权限 600，与插件默认位置一致。状态目录设为 700；确保 `~/Library/LaunchAgents` 存在。

`mac-privacy-guard.plist` 用 `__HOME__` 占位。替换成本机路径后验证，再加载：

```sh
sed "s|__HOME__|$HOME|g" mac-privacy-guard.plist > ~/Library/LaunchAgents/local.opencode-go.privacy-guard.plist
plutil -lint ~/Library/LaunchAgents/local.opencode-go.privacy-guard.plist
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/local.opencode-go.privacy-guard.plist
```

该操作只启动本地服务，不会自动打开插件的 `privacyEnabled`。先验证 `/mask`，再设置插件并重新加载它。

模板只设置 `CLIENT_API_KEY_FILE`，不设置 `UPSTREAM_URL`。这样进程只做扫描和 `/mask`，不会把任何请求转发出去。

## 检查

```sh
curl -s http://127.0.0.1:8788/healthz
```

Coder 上应看到 `"mode":"proxy"`。是否可逆看启动日志里的 `reversible=true`，`/healthz` 不返回这个字段。Mac 上应看到 `"mode":"scan-only"`。
