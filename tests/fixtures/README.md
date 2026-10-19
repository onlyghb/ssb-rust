# 原版对照样本

`upstream.json` 由原 Go 程序实际运行产生，来源：
[onlyghb/ssb @ 69147358600170b45e440a3aaf7dea0a965fa22d](https://github.com/onlyghb/ssb/tree/69147358600170b45e440a3aaf7dea0a965fa22d)。

包含 11 个分享链接的 `link.Parse` 结果和 64 组 `render.Build` 配置。
配置组合覆盖 IPv6 探测与 on/off 覆盖、rule/global、Dashboard、TUN、FakeIP、
自动测速与空节点、auto_redirect、自定义分流、规则集源、镜像和下载出站。
工作目录统一 `/ssb-parity`、密钥统一 `parity-secret`。

样本生成时使用原版 `profile.Load` 获取默认状态，覆盖上述设置，并注入
`render.HostHasIPv6` 模拟不同内核能力。原版的 nil slice 保留为 JSON null，
同时验证 Rust 状态反序列化的迁移兼容性。`tests/upstream.rs` 对解析结果和
配置做 JSON 值比较（归一化 Windows 路径，并应用以下明确的修复）。原样本保持不变：

- FakeIP 关闭时增加 `dns.reverse_mapping: true`，让真实 IP 路由可恢复域名。
- 自定义强制代理域名的 FakeIP 规则限制为 A/AAAA 查询，并追加代理 DoH 规则处理其他查询类型。
- TUN 始终开启 `strict_route`；IPv6 关闭或自动降级时，在业务路由前拒绝 IPv6 连接。
- 无节点时，在其他分流之前拒绝所有连接和 DNS 查询；ssb 同时禁止启动内核。

其他配置字段仍做完整比较，修复行为另由配置测试覆盖。
