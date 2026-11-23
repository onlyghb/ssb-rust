# ssb

基于 sing-box 1.14 的节点与订阅管理器，提供终端界面、命令行和可选网页面板。

- 节点：VLESS、AnyTLS、Shadowsocks、VMess、Trojan、Hysteria2、TUIC
- 订阅：sing-box、Clash、明文或 Base64，显示流量与到期信息
- 分流：TUN、SOCKS5/HTTP、FakeIP、国内直连、自定义域名、自动测速

## 安装

从 [Releases](https://github.com/onlyghb/ssb-rust/releases/latest) 下载压缩包（Linux `.tar.gz`、Windows `.zip`，均有 amd64 / arm64），解压到独立目录。带 `with-singbox` 的完整包已含内核，精简包先运行 `ssb install`。

```bash
./ssb install  # 完整包可跳过
sudo ./ssb     # Windows：以管理员身份运行 .\ssb.exe
```

TUN 需要 root/CAP_NET_ADMIN 或管理员权限。不用 TUN 时执行 `ssb settings set tun_enabled false`，改用 `socks5://127.0.0.1:2080` 或 `http://127.0.0.1:2080`。

## 终端界面

| 按键 | 操作 |
| --- | --- |
| `1–4` / `Tab` | 切换状态、订阅、节点、设置 |
| `↑ ↓` / `j k` | 移动光标或翻阅日志 |
| `/` | 搜索当前列表 |
| `a` | 添加订阅（`URL 名称`）或节点（可粘贴多行） |
| `Enter` / 空格 | 切换出口或修改设置 |
| `e` | 编辑设置原始值 |
| `t` | 节点测速（需内核运行） |
| `u` / `U` | 更新当前 / 全部订阅 |
| `x` | 删除订阅或手动节点 |
| `s` / `r` | 启停内核 / 重启以应用配置 |
| `g` | 生成并校验配置 |
| `?` / `q` | 帮助 / 退出（内核继续运行） |

## 命令行

```text
ssb add "vless://…"            添加节点，也可从 stdin 输入
ssb sub add <URL> [名称]        添加订阅
ssb sub update [名称]           更新指定或全部订阅
ssb sub ls | sub rm <名称>      列出或删除订阅
ssb nodes | nodes rm <tag>      列出节点或删除手动节点
ssb select <tag>               切换出口
ssb start | stop | restart     启停内核
ssb status | logs [-f]         状态与日志
ssb install                    下载最新稳定版内核
ssb gen                        生成并校验配置
ssb settings [set <键> <值>]    查看或修改设置
ssb dashboard                  面板地址与密钥
ssb doctor                     环境与安全检查
ssb run-core                   前台运行内核
```

## 配置

- 默认国内直连、其余走 PROXY，路由模式可选 `rule` / `global`；自定义分流优先，`example.com` 含子域名，`.cn` 仅匹配后缀。
- 国内 DNS 填 IP；代理 DNS 支持 IP、域名或 HTTPS DoH URL。
- IPv6 可选 `auto` / `on` / `off`，未启用时拒绝 IPv6 连接。TUN 开启严格路由（内核以 `ipv6.disable=1` 启动时除外）。
- 无节点时拒绝启动内核，配置阻断全部连接和 DNS。
- 规则集默认从 jsDelivr 下载，可改用 GitHub 源或 `https://` 镜像；经镜像下载的内核按 SHA-256 校验。
- 网页面板：`ssb settings set dashboard_off false`，重启后用 `ssb dashboard` 查看地址和密钥。
- `gen` 和 `doctor` 会提示未校验证书或未加密的节点、明文订阅、对外监听的 API 等风险。

数据目录默认为可执行文件所在目录，可用 `--dir` 或 `SSB_DIR` 指定；升级时替换可执行文件、保留 `data/`。`data/state.json` 含节点凭据、订阅地址和 API 密钥，请妥善保管。

## 从源码构建

需要 Rust 1.88+ 和 C 编译器：

```bash
cargo build --release --locked
docker compose build && docker compose up -d  # 或使用 Docker
```

## 许可

[MIT](LICENSE)。完整包附带的 [sing-box](https://github.com/SagerNet/sing-box) 遵循 GPL-3.0，版权归 SagerNet；对应源码链接随包提供。
