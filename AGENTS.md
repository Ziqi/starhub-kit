# StarHub Kit 全智能体与运维总入口 (`AGENTS.md`)

> **版本**：`v1.3.0`（软件规范对齐 `StarHub Home OS v2.0-spec`） · **权威性声明**：本文件是 `starhub-kit` 唯一根级指令入口（根目录 `CLAUDE.md` 与 `GROK.md` 均为指向本文件的 POSIX 软链接，彻底杜绝多入口分裂）。机器可读唯一事实源位于 [STARHUB_GROUND_TRUTH.json](STARHUB_GROUND_TRUTH.json)。

---

## 1. 标准中立角色拓扑、RFC 示例地址与职责边界总表

> 说明：本开源仓采用纯角色化（Role-Based）中立命名与符合 RFC 5737 / RFC 6598 / RFC 3849 / RFC 7042 标准的参考拓扑，部署时仅需在 `STARHUB_GROUND_TRUTH.json` 替换为您的实际地址并执行 `./bin/starhub render --in-place`。

| 标准角色名 | SSH 短名字 | 局域网 / 公网示例地址 | Mesh (`100.64.0.x` / `2001:db8::`) | 核心职责与安全边界 |
|---|---|---|---|---|
| **虚拟化宿主机** | **`ssh pve`** | `192.0.2.10` | `2001:db8:4a6::10` (`4via6`) | Proxmox VE 虚拟化宿主机（为 LXC 102/103 透传 `/dev/net/tun`；经 `4via6` 免子网撞段访问） |
| **透明网关总闸** | **`ssh gw`** / **`ssh gw-rescue`** (`:2203`) | `192.0.2.11`<br/>副 IP `192.0.2.12` | `100.64.0.11`<br/>`2001:db8:a1e0::11` | LXC 100 透明网关：Mihomo `gvisor` TUN + 确定性分域 DNS（兼任 `.12` 备用 DNS VIP）+ Exit Node + 摄像头断云闸 + `:2203` 救命绳 |
| **观测控制中枢** | **`ssh panel`** | `192.0.2.15` | `100.64.0.15`<br/>`2001:db8:a1e0::15` | LXC 102 观测与控制中枢：`:3001` 16 项健康探针 + 双栈白名单防火墙 + 唯一权威工作区 + EGM 3.0 Doctor |
| **智能与AI中枢** | **`ssh home`** | `192.0.2.20` | `100.64.0.20`<br/>`2001:db8:a1e0::20` | LXC 103 全屋智能与 AI 中枢：`StarHub Home OS v2.0-spec`（`:8080` + 双栈白名单 + `shome` CLI） |
| **随身主控笔电** | **`ssh laptop`** | `192.0.2.31` | `100.64.0.31` | 随身主控笔电（`127.0.0.1:17890` 三级自适应回环隧道，规避远程会话本地网络门禁拦截） |
| **算力工作站** | **`ssh workstation`** / **`ssh workstation-rescue`** (`:2204`) | `192.0.2.32` | `100.64.0.32` | 7×24 高吞吐算力工作站：独享 `vps2` (`198.51.100.12`) 物理分流 + 主机防火墙单向与局域网入站隔离 + `:2204` 救命绳 |
| **异地边缘节点** | **`ssh site-b-node`** / **`ssh site-b-node-rescue`** (`:2202`) | `198.51.100.41` | `100.64.0.41` | 异地常驻节点：本机 `127.0.0.1:7890` (`0600`) + 60s 自愈看门狗 + `:2202` 救命绳 |
| **单向受控训练机** | **`ssh gpu-worker`** / **`ssh gpu-worker-rescue`** (`:2201`) | `198.51.100.42` | `100.64.0.42` | 异地 GPU 训练机：**严格单向受控**（`ForwardAgent no`、`accept-routes=false`、`exit-node=""`）+ `:2201` 救命绳 |
| **海外三出口** | **`ssh vps1` / `vps2` / `vps3`** | `198.51.100.11` / `198.51.100.12` / `198.51.100.13` | — | `sing-box` VLESS-Reality `:443`（全量 `bbr+fq`）：主用出口 `vps1`、工作站专享 `vps2`、中转与异网灾备 `vps3` |
| **自建中继跳板** | **`ssh derp`** | `203.0.113.10` | `100.64.0.254` | 自建 Region `901` DERP（`derp.example.net` `:443->:8443` / STUN `:3478`）+ 四路反向救命绳 `127.0.0.1:2201..2204` |
| **云端 AI 沙箱** | —（受限访客 `B2`） | — | `100.64.0.201` / `100.64.0.202` | 临时云沙箱池：按实例隔离 `/tmp/tailscale-<id>`，仅放行 `:3001`/`:8080` Web API，`STARHUB-BOT-NOSSH` 硬丢弃 `:22` SSH |

---

## 2. 「1 核 + 6 册 + 2 账」按需阅读索引

- **中英双语总览**：[README.md](README.md) (EN) · [README.zh-CN.md](README.zh-CN.md) (ZH)
- **机器事实核**：[STARHUB_GROUND_TRUTH.json](STARHUB_GROUND_TRUTH.json)（示例模板 [topology.example.json](topology.example.json)）
- **黄金六册与扩展规范**：
  1. [docs/01-架构与IP全景.md](docs/01-架构与IP全景.md) —— 零撞段组网、确定性分域 DNS、`Section 9a` 前置 QUIC 治理与出口拓扑
  2. [docs/02-日常运维与变更升级.md](docs/02-日常运维与变更升级.md) —— 十大铁律、守护进程地图、凭据与单向受控矩阵、声明式变更 SOP
  3. [docs/03-排障与急救手册.md](docs/03-排障与急救手册.md) —— 30 秒诊断树、四路救命绳与 1 小时裸机灾难重建（DR）
  4. [docs/04-日志与审计索引.md](docs/04-日志与审计索引.md) —— 全网日志速查、双台账规范与编译器产物映射表
  5. [docs/05-智能家居与AI中枢全景.md](docs/05-智能家居与AI中枢全景.md) —— 摄像头物理断云闸、电视软黑屏待机与局域网 IoT 边界守则
  6. [docs/06-AI接力开发与Prompt手册.md](docs/06-AI接力开发与Prompt手册.md) —— 多智能体协同宪章与自动化巡检工作流
  7. [docs/ROADMAP-v2.md](docs/ROADMAP-v2.md) —— `v2.0` 看板动态探针与 `Home OS` 硬件驱动插件接口规范
- **唯一双台账**：
  - [docs/ops/STARHUB-LEDGER.md](docs/ops/STARHUB-LEDGER.md) —— `[UPD]` + `[BUGFIX]` + `[WORKSTATION]` 统一动态主台账
  - [docs/incidents/README.md](docs/incidents/README.md) —— 重大事故 `5-Why` 深度复盘库与标准模板

---

## 3. 星枢十大不可违背铁律（Ten Iron Guardrails）

1. **唯一事实源与一源编译**：严禁手工散改多份防火墙或规则文件；一切节点/IP 变更先改 `STARHUB_GROUND_TRUTH.json`，再由 `./bin/starhub render` 确定性生成并经 `render --check` 验真。
2. **多站点独立出海与高负载分流**：各地域网关直连海外 VLESS-Reality 节点，严禁跨城套娃；7×24 高吞吐算力工作站专享独立出口 `vps2` (`198.51.100.12`)，与日常办公流量物理隔离。
3. **非对称单向受控原则**：无人值守算力机（`gpu-worker`）永久锁定 `accept-routes=false`、`exit-node=""`、禁用反向 SSH 公钥；主控端连入受控工作站强制配置 `ForwardAgent no` 与 `IdentitiesOnly yes`。
4. **远程会话免门禁本地回环隧道**：桌面主控机经 SSH/tmux 远程开发时，统一通过豁免门禁的系统原生 `/usr/bin/ssh` 暴露 `127.0.0.1:17890` 回环代理口，规避第三方二进制触发本地网络隐私拦截。
5. **Tailscale 防环直连豁免**：透明网关 Mihomo 规则顶部必须前置 `DIRECT` 豁免 `*.tailscale.com`、`*.ts.net`、自建 DERP 域名/IP、`DST-PORT,3478`、`100.64.0.0/10` 及全部海外出口公网 IP。
6. **确定性分域 DNS 与 `Section 9a` 前置 QUIC 治理**：严禁使用盲目双发竞速 `fallback:` 段；开启 `respect-rules: true` 与 `nameserver-policy`；在广义 Google 代理规则上方（`Section 9a`）对 Apple 媒体与 Gmail/内嵌图附件精确域名执行 `UDP/443 REJECT`，**严禁全局封杀 `UDP/443` 或拦截 YouTube Cronet 域名**。
7. **智能家居局域网自治与软待机守则**：IoT 摄像头通过网关 `mangle FORWARD` 实现一键物理断云（保留局域网直看）；智能电视保持系统全局直连（`:0`），仅在特定跨境应用内配置代理，网页待机一律采用不断网软黑屏（严禁触发断电关 Wi-Fi 的硬件休眠键码）。
8. **云端 Agent `B2` 沙箱隔离边界**：云端容器沙箱必须按实例隔离 `--statedir=/tmp/tailscale-<id>`，目标主机双栈防火墙必须通过 `STARHUB-BOT-NOSSH` / `NOSSH6` 硬拦截全部 `:22` SSH。
9. **凭据零入库与 `0600` 锁权**：严禁将任何 `.env`、私钥、UUID 或非空 `secret` 提交入 Git；线上敏感配置统一锁定 `chmod 0600`。
10. **StarHub EGM 3.0 门禁闭环**：严禁在白名单外创建野 `.md` 文档；每次变更提交前必须运行 `./bin/starhub doctor --local-docs-only`（全栈实机环境运行 `./bin/starhub doctor`）确保 `FAIL=0`。

---

## 4. 标准自检与构建口令

```bash
# 1. 校验声明式编译器零漂移 + 7 维离线 EGM 门禁
./bin/starhub render --check && ./bin/starhub doctor --local-docs-only

# 2. 导出全量上机部署产物至 ./dist
./bin/starhub render --out-dir ./dist
```
