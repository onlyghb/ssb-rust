# ssb

## 功能

- 管理 VLESS、AnyTLS、Shadowsocks、VMess、Trojan、Hysteria2、TUIC 节点。
- 导入 sing-box、Clash、明文或 Base64 订阅，显示流量与到期信息。
- 支持 TUN、SOCKS5/HTTP、FakeIP、国内直连、自定义域名分流和自动测速。
- 提供终端界面、命令行和可选网页面板，适配 sing-box 1.14。

## 安装

从 [Releases](https://github.com/onlyghb/ssb-rust/releases/latest) 下载对应平台的压缩包，解压到独立目录：

| 平台 | 架构 | 文件后缀 |
| --- | --- | --- |
| Linux | amd64 / arm64 | `.tar.gz` |
| Windows | amd64 / arm64 | `.zip` |

带 `with-singbox` 的完整包已包含内核；精简包先运行 `ssb install` 下载内核。

Linux：

```bash
chmod +x ssb
./ssb install  # 完整包可跳过
sudo ./ssb
```

Windows：

```powershell
.\ssb.exe install  # 完整包可跳过
.\ssb.exe
```

TUN 需要 Linux root/CAP_NET_ADMIN 或 Windows 管理员权限。不使用 TUN 时可关闭：

```bash
./ssb settings set tun_enabled false
./ssb
```

此时可使用 `socks5://127.0.0.1:2080` 或 `http://127.0.0.1:2080`。
Windows 命令中的 `./ssb` 替换为 `.\ssb.exe`。

## 终端界面

运行 `ssb` 进入界面：

| 按键 | 操作 |
| --- | --- |
| `1–4` / `Tab` | 切换状态、订阅、节点、设置 |
| `↑ ↓` / `j k` | 移动光标或翻阅日志 |
| `/` | 搜索当前列表，Enter 保留筛选，Esc 清除 |
| `a` | 添加订阅或节点，支持粘贴多行链接 |
| `Enter` / 空格 | 切换节点出口，或修改设置 |
| `u` / `U` | 更新当前 / 全部订阅 |
| `x` / `Delete` | 删除订阅或手动节点 |
| `e` / `Backspace` | 编辑设置原始值 / 反向轮转设置 |
| `s` | 启动或停止内核 |
| `r` | 重启并应用配置改动 |
| `g` | 生成并校验配置 |
| `?` | 查看完整帮助 |
| `q` | 退出界面，内核继续在后台运行 |

订阅可按 `URL 名称` 输入。有节点时，节点页的 `auto` 自动选择低延迟节点，`direct` 直接连接。
无节点时禁止启动内核，生成的配置会阻断连接和 DNS 查询；请先添加节点或订阅。
宽屏在右侧显示详情，普通尺寸在列表下方显示。输入有误时可直接修正；设置校验失败保留原配置。
配置有改动时按 `r` 应用，再切换出口。

## 命令行

```text
ssb add "vless://…"                     添加节点，也可从 stdin 输入
ssb sub add <URL> [名称]                 添加订阅
ssb sub update [名称]                    更新指定或全部订阅
ssb sub ls | sub rm <名称>               列出或删除订阅
ssb nodes | nodes rm <tag>               列出节点或删除手动节点
ssb select <tag>                        切换运行中的 PROXY 出口
ssb start | stop | restart | status      内核启停与状态
ssb install                             下载最新稳定版内核
ssb gen                                 生成并校验配置
ssb settings                            查看设置
ssb settings set <键> <值>               修改设置
ssb dashboard                           查看面板地址与密钥
ssb logs [-f]                           查看或跟随日志
ssb doctor                              环境检查
ssb run-core                            前台运行内核
ssb version | help                      版本与帮助
```

## 配置

- 默认国内域名/IP 直连，其余通过 PROXY；路由模式可选 `rule` / `global`。
- 自定义分流优先于中国规则。`example.com` 包含自身和子域名，`.cn` 仅匹配后缀。
- 国内 DNS 使用 IP 地址；代理 DNS 支持 IP、域名或完整 HTTPS DoH URL。
- IPv6 可选 `auto` / `on` / `off`；`auto` 按系统能力探测。关闭或降级时，TUN 阻断 IPv6，显式代理也拒绝 IPv6 目标连接。
- TUN 始终开启严格路由；无法安装所需路由或阻断规则时拒绝启动。
- 规则集默认从 jsDelivr 直连下载，可切换 GitHub 源或设置镜像前缀。
- 开启网页面板：`ssb settings set dashboard_off false`，重启后运行 `ssb dashboard` 获取地址和密钥。

默认数据目录为可执行文件所在目录，可用 `--dir <目录>` 或 `SSB_DIR` 指定。
升级时替换可执行文件，保留 `data/`；配置上一版备份为 `data/config.json.bak`，日志位于 `logs/`。
`data/state.json` 包含节点凭据、订阅地址和 API 密钥，请妥善保管。

## 从源码构建

需要 Rust 1.88+ 和 C 编译器：

```bash
cargo build --release --locked
cargo run -- --dir ./workspace
```

Docker：

```bash
docker compose build
docker compose run --rm ssb add "vless://…"
docker compose up -d
```

## 许可

[MIT](LICENSE)。完整包附带的 [sing-box](https://github.com/SagerNet/sing-box)
遵循 GPL-3.0，版权归 SagerNet；对应源码链接随包提供。
