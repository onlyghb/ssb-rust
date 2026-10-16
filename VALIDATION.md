# 验证记录

## 2026-10-16：TUI 与 DNS 优化

- `cargo test --locked`：34 项测试通过，包含中文实时搜索、筛选后操作目标、空节点列表、非法输入保留及设置校验失败回滚。
- 严格 Clippy、格式化检查和原生 release 构建通过。
- 真实 PTY：中文多行粘贴、实时搜索、筛选删除、端口纠错、帮助、缩小窗口和退出恢复。
- 官方最新稳定版 sing-box 1.14.3：配置校验、后台启停、API 查询/切换、本地 mixed 代理请求、重启、体检、订阅、设置和备份流程通过。
- 使用该内核额外校验 48 组配置：TUN/mixed、FakeIP/真实 IP、IPv6 on/off、rule/global，以及普通 IP、含查询参数的 DoH URL 和 IPv6 DoH URL。
- 原 Go 配置对照保留 64 组覆盖，仅允许 `tests/fixtures/README.md` 记录的两处 DNS 修复差异。

本轮实际启动内核时均关闭 TUN；TUN 配置仅执行 `sing-box check`。
Windows 本轮未进行实机验证。以下为首次迁移时的历史验证记录。

## 首次迁移

本机：Linux ARM64。迁移依据：`onlyghb/ssb@69147358600170b45e440a3aaf7dea0a965fa22d`。

已通过：

- `cargo fmt --check` 和 `cargo clippy --all-targets --locked -- -D warnings`。
- `cargo test --locked`：30 项测试全部通过。
- 原 Go 实现实际生成的 11 个节点与 64 组配置，完整 JSON 对照一致。
- Rust 1.88.0：`cargo check --all-targets --locked`，验证最低支持版本。
- Windows x64：`x86_64-pc-windows-gnu` 全目标检查与严格 Clippy；Windows ARM64：`aarch64-pc-windows-gnullvm` 全目标检查。
- Linux 原生 release 和 `aarch64-unknown-linux-musl` 静态 release 构建；静态版本没有 ELF 动态节或动态库依赖。
- 真实 sing-box 1.14.0 / 1.14.2：配置校验、后台启停、API 查询与出口切换、本地 HTTP 请求通过 mixed 端口、重启、doctor、订阅 CRUD、设置、备份。
- 实际 jsDelivr 规则集下载与官方 Dashboard 下载/托管；日志没有 WARN/FATAL。
- Rust `install` 命令实际通过 GitHub Release API 下载 sing-box 1.14.2 并校验配置。
- 真实 PTY：页签、中文多行粘贴、添加/删除节点、设置修改、帮助、窗口缩小、终端恢复与退出。
- Docker 镜像构建、Compose 语法，以及隔离网络下的配置生成、`run-core`、API 与 SIGTERM 正常退出。
- 静态 Linux ARM64 精简包与完整包（附 sing-box 1.14.2）实际生成并检查；产物在 `dist/`。

全部真实运行测试均关闭 TUN，不修改宿主网络路由。TUN 配置的字段与 IPv6 降级通过配置测试和 `sing-box check` 验证。
Windows 的管理员权限、TUN 网卡与关闭控制台后的行为尚未在 Windows 实机运行；跨平台 CI 已配置，尚未推送执行。

复现命令见 `README.md`。本次临时编译工具位于 `/tmp/ssb-cargo`、`/tmp/ssb-rustup`；
本机没有预装 Rust 时，可在该会话中设置 `CARGO_HOME`、`RUSTUP_HOME` 并使用 `/tmp/ssb-cargo/bin/cargo`。
