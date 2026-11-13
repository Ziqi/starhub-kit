# StarHub Kit 星枢开源套件 (`starhub-kit`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![StarHub EGM 3.0 CI](https://github.com/Ziqi/starhub-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/Ziqi/starhub-kit/actions/workflows/ci.yml)
[![CodeQL SAST](https://github.com/Ziqi/starhub-kit/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ziqi/starhub-kit/actions/workflows/codeql.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/Ziqi/starhub-kit/attestations)
[![Supply-Chain Attestations](https://github.com/Ziqi/starhub-kit/actions/workflows/attestation.yml/badge.svg)](https://github.com/Ziqi/starhub-kit/attestations)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Ziqi/starhub-kit/badge)](https://scorecard.dev/viewer/?uri=github.com/Ziqi/starhub-kit)
[![SBOM: SPDX 2.3](https://img.shields.io/badge/SBOM-SPDX%202.3-00599C.svg)](https://github.com/Ziqi/starhub-kit/releases/latest)
[![REUSE 3.2](https://img.shields.io/badge/REUSE-3.2%20SPDX-brightgreen.svg)](https://reuse.software/)

> **语言切换 (Language)**：[English](./README.md) | **简体中文**  
> **版本**：`v1.0.2` · **开源协议**：[MIT](./LICENSE)（兼容 `SPDX-2.3` / `REUSE 3.2`） · **供应链证书**：Sigstore `SLSA Build Level 3` + Ed25519 离线签名 · **运行依赖**：Python 3.9+ 标准库（零第三方依赖）

**StarHub Kit（星枢开源套件）** 是一套经过跨地域多站点 7×24 实战锤炼的 **声明式异地零撞段组网 + 抗断流透明网关 + 带外反向救命绳 + AI 防幻觉工程治理（`StarHub EGM 3.0`）** 开源基础设施脚手架。

只需修改一份机器可读的拓扑总表 [STARHUB_GROUND_TRUTH.json](./STARHUB_GROUND_TRUTH.json)，执行 `./bin/starhub render`，即可确定性编译生成：双栈白名单防火墙（`iptables` + `ip6tables`）、Mihomo 确定性分域 DNS 与精准应用层 QUIC 治理母版、云端 AI 沙箱（`B2`）受限访客引导脚本、物联网摄像头网关级物理断云总闸（`cam-gate.sh`）、SSH 短名字配置与四路反向 SSH 救命绳 `systemd` 服务——并内置八维零漂移门禁与数学级反隐私泄露扫描器。

---

## 为什么需要 StarHub Kit？（直击四大实战深水区痛点）

| 传统家庭实验室 / 跨地域组网痛点 | 星枢 3.0 工程化解法 |
|---|---|
| **1. 出门连酒店/咖啡厅 Wi-Fi 内网撞段失联**<br/>传统子网路由在异地同名 `/24` 局域网下会触发内核路由优先级抢占，导致网关与容器瞬间断联。 | **原生 `100.x` + `4via6` 零撞段架构**<br/>核心 LXC 容器直通 `/dev/net/tun` 启用原生 `100.64.0.x`；不便装客户端的宿主机通过 `4via6` 纯 IPv6 映射访问，配合 `STARHUB-IPV6-EXIT-GUARD` 杜绝双栈泄漏。 |
| **2. 透明网关跨洋半开断流与 QUIC 黑洞**<br/>盲目配置 DNS `fallback:` 双发竞速导致日均数百次 `context canceled`；Apple TV+ 与手机 Gmail 因跨境 XUDP `UDP/443` 黑洞干等 50s，而粗暴封杀全局 `UDP/443` 又会误伤 YouTube Cronet 字幕。 | **确定性分域 DNS + 手术刀级 QUIC 治理**<br/>彻底移除 `fallback:` 竞速（纯 `nameserver-policy` 确定性路由），仅针对 Apple 媒体（`Section 12b`）与 Gmail（`Section 12c`）精确域名执行 `UDP/443 REJECT`，并由 `doctor` 自动校验零误伤 YouTube Cronet。 |
| **3. 云端 AI 沙箱撞号失步与内网横向渗透风险**<br/>多实例云端 Agent 共用 Tailscale 状态文件会引发 `NodeKey` 抢占断流；若直接放通内网更会暴露 `:22` SSH 与容器管理口。 | **`B2` 受限访客直通沙箱协议**<br/>通过 `grokbot-tailscale-bootstrap.sh` 按实例隔离 `/tmp/tailscale-<id>`，双栈防火墙 `STARHUB-BOT-NOSSH` / `NOSSH6` 仅放行 `:3001`/`:8080` Web API，硬件级 `DROP` 全部 `:22` SSH。 |
| **4. 运维文档腐败膨胀、配置漂移与开源泄密风险**<br/>几十份历史 Markdown 互相打架，AI 助手反复读取旧 IP 产生幻觉；想分享架构又担心泄露真实公网 IP 与硬件指纹。 | **StarHub EGM 3.0（「1 核 + 6 册 + 2 账」）**<br/>根部 `AGENTS.md`（`CLAUDE.md`/`GROK.md` 软链归一）、活跃文档白名单锁死、`render --check` 零漂移校验，以及逐字节扫描工作树与 `.git` 历史的 `--verify-public-export` 反隐私门禁。 |

---

## 3 分钟快速上手（Quickstart）

```bash
# 1. 克隆仓库并从标准示例生成您的唯一拓扑事实源
git clone https://github.com/Ziqi/starhub-kit.git
cd starhub-kit
./bin/starhub init

# 2. 按需编辑 STARHUB_GROUND_TRUTH.json 中的节点与出口 IP，一键原位重编译受控脚本
./bin/starhub render --in-place

# 3. 导出全套可上机部署包（双栈防火墙、Mihomo 网关配置骨架、摄像头断云闸、SSH 配置片段、救命绳单元）
./bin/starhub render --out-dir ./dist

# 4. 运行 7 维离线 EGM 门禁自检与 2,000 轮编译器模糊测试（零网络请求）
./bin/starhub doctor --local-docs-only
python3 ./tests/fuzz_starhub_ctl.py --iterations 2000

# 5. 安装 Git 提交前自动门禁钩子
cp scripts/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

---

## 「1 核 + 6 册 + 2 账」工程目录导航

1. **机器事实核**：[STARHUB_GROUND_TRUTH.json](./STARHUB_GROUND_TRUTH.json)（示例母版 [topology.example.json](./topology.example.json)）
2. **统一 AI 与人工总入口**：[AGENTS.md](./AGENTS.md)（`CLAUDE.md` 与 `GROK.md` 均为指向它的 POSIX 软链接）
3. **黄金六册蓝图手册**：
   - [docs/01-架构与IP全景.md](./docs/01-架构与IP全景.md) —— 零撞段拓扑、分域 DNS、精确 QUIC 治理与三出口架构
   - [docs/02-日常运维与变更升级.md](./docs/02-日常运维与变更升级.md) —— 十大铁律、常驻服务地图、凭据 `0600` 与单向受控矩阵、标准变更 SOP
   - [docs/03-排障与急救手册.md](./docs/03-排障与急救手册.md) —— 30 秒诊断树、四路救命绳（`:2201~:2204`）与 **1 小时裸机灾难重建（DR）**
   - [docs/04-日志与审计索引.md](./docs/04-日志与审计索引.md) —— 全链路日志定位、双台账规范与编译器映射表
   - [docs/05-智能家居与AI中枢全景.md](./docs/05-智能家居与AI中枢全景.md) —— 摄像头网关物理断云闸、Android TV 不断网软待机与分应用代理守则
   - [docs/06-AI接力开发与Prompt手册.md](./docs/06-AI接力开发与Prompt手册.md) —— 多智能体协同宪章（CLI + `tmux` / 云端 `B2` / 移动端 Moshi）与扩展蓝图
4. **`v2.0` 插件化演进规范**：[docs/ROADMAP-v2.md](./docs/ROADMAP-v2.md)（定义 `:3001` 看板动态探针与 `:8080` `Home OS` 硬件驱动插件接口契约）
5. **唯一双台账**：[docs/ops/STARHUB-LEDGER.md](./docs/ops/STARHUB-LEDGER.md) 与 [docs/incidents/README.md](./docs/incidents/README.md)（含标准 `5-Why` 复盘模板 [_template.md](./docs/incidents/_template.md)）

---

## 供应链数字证书验真与社区治理

每次主干构建与版本发布均自动签发 **Sigstore + GitHub OIDC `SLSA Build Level 3` X.509 溯源证书**、**ISO/IEC 5962 (`SPDX-2.3`) 软件物料清单（SBOM）** 与 **Ed25519 离线数字签名**：

```bash
# 一键验真 GitHub OIDC / Sigstore SLSA Build Level 3 密码学构建溯源证书
gh attestation verify starhub-kit-bundle.tar.gz --repo Ziqi/starhub-kit
```

本项目基于 [MIT License](./LICENSE) 协议开源。提交 PR 前请先阅读 [GOVERNANCE.md](./GOVERNANCE.md)、[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)、[CONTRIBUTING.md](./CONTRIBUTING.md) 与 [SECURITY.md](./SECURITY.md)（含第 5 节架构威胁模型与安全保证论证）。
