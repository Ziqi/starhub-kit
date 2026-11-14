# StarHub Kit 全域统一变更与故障闭环主台账 (`STARHUB-LEDGER`)

> **版本**：`StarHub Kit v1.3.0`  
> **设计原则**：告别在多份零散文档中重复抄写流水的传统做法，一切**架构演进 `[UPD]`**、**缺陷根因闭环 `[BUGFIX]`** 与**算力工作站专项变更 `[WORKSTATION]`** 均按时间倒序（Append-Only，最新在最上方）统一追加于本账本。  
> **关联索引**：
> - 静态机器事实源（SSOT）：[STARHUB_GROUND_TRUTH.json](../../STARHUB_GROUND_TRUTH.json) · [mihomo-shared-guardrails.yaml](../../scripts/profiles/mihomo-shared-guardrails.yaml)
> - 重大事故 `5-Why` 复盘库：[docs/incidents/README.md](../incidents/README.md)
> - 按 `[WORKSTATION]` 标签单独导出算力工作站变更摘要：`./bin/starhub export-workstation`

---

## 一、快速检索总表（Master Index）

| 条目 ID | 标签 | 日期 | 涉及模块 | 一句话摘要 |
|---|---|---|---|---|
| [UPD-20261114-003](#upd-20261114-003) | `[UPD][SECURITY][MCP]` | 2026-11-14 | `starhub-ctl` / `profiles` / `tests` / `README` | **StarHub Kit `v1.3.0` 自主 AI 沙箱防火墙预设（`ai-sandbox`）、跨平台四后端（`nftables` / `macOS pf` / `Tailscale ACL` / `Sing-box`）与零依赖原生 `MCP Server` 发布**：打通 Claude Code / Cursor / Codex 内网防渗透隔离与主流操作系统/代理栈一键导出 |
| [UPD-20261114-002](#upd-20261114-002) | `[UPD][UX][SECURITY]` | 2026-11-14 | `starhub-ctl` / `README` / `SECURITY` / `flake.nix` | **StarHub Kit `v1.2.0` 模块化无特权预览（`--only` + `--dry-run`）、逐比特可重现归档（`archive --verify`）、原生 Nix Flake 与 OSPS Baseline L3 对齐发布**：降低外部上手门槛，首屏去内部代号化并内嵌 15 秒高清矢量终端动图 |
| [UPD-20261114-001](#upd-20261114-001) | `[UPD][UX][OSS]` | 2026-11-14 | `profiles` / `starhub-ctl` / `docs` | **StarHub Kit `v1.1.0` 三级轻量化接入矩阵与英文协议排障手册发布**：新增零编译即贴即用规则包 `standalone-mihomo-tailscale-guardrails.yaml`、`StarHub Lite` 单网关极简模板（`--profile minimal`）及英文核心协议深潜手册 `ARCHITECTURE-AND-PLAYBOOK-EN.md` |
| [UPD-20261113-004](#upd-20261113-004) | `[UPD][SECURITY][OSS]` | 2026-11-13 | 全仓拓扑 / `README` / `starhub-ctl` / `starhub-doctor` | **StarHub Kit `v1.0.3` 获颁 OpenSSF Silver 银牌认证（`#16658`）、全量角色化去指纹重构与移动端 Gmail `Section 9a` 前置规则同步**：正式挂载 OpenSSF Best Practices `Silver` 徽章（`200%`），将全部节点/IoT/出口重构为通用中立工程角色，补齐移动端 Gmail 内嵌图/附件 `UDP/443 REJECT` 前置防遮蔽母版，并升级 `--verify-public-export` 硬件画像反泄露门禁 |
| [UPD-20261113-003](#upd-20261113-003) | `[UPD][SECURITY][OSS]` | 2026-11-13 | `.github` / `scripts` / `tests` / `GOVERNANCE.md` | **StarHub Kit `v1.0.2` SLSA Level 3 证书、SPDX 2.3 SBOM 与 OpenSSF Silver 银牌基线落地**：新增 Sigstore OIDC `SLSA Build Level 3` 构建溯源证书工作流、`SPDX-2.3` SBOM 生成器、`fsfe/reuse-action` 强校验、`SECURITY-INSIGHTS.yml`、`GOVERNANCE.md` / `CODE_OF_CONDUCT.md` 及 `>=80%` 语句覆盖率 CI 门禁 |
| [UPD-20261113-002](#upd-20261113-002) | `[UPD][SECURITY][OSS]` | 2026-11-13 | `tests` / `.github` / `SECURITY.md` | **StarHub Kit `v1.0.1` OpenSSF 深度供应链加固**：新增 `atheris` + 标准库双模模糊测试引擎（`tests/fuzz_starhub_ctl.py`）、`CODEOWNERS` 与分支保护、CodeQL `v4.39.3` 成组原子更新，以及 Ed25519 + SLSA/in-toto 签名溯源发布 |
| [UPD-20261113-001](#upd-20261113-001) | `[UPD][EGM][OSS]` | 2026-11-13 | `starhub-ctl` / `starhub-doctor` / `docs` | **StarHub Kit `v1.0.0` 首个净室开源版发布**：落地零依赖声明式拓扑编译器、`100.x + 4via6` 零撞段组网蓝图、确定性分域 DNS 与 Apple/Gmail 精确 QUIC 治理、四路救命绳、摄像头断云闸及 EGM 3.0 八维门禁 |
| [WORKSTATION-UPD-20261113-001](#workstation-upd-20261113-001) | `[WORKSTATION][UPD]` | 2026-11-13 | `workstation` (`100.64.0.32`) | **算力工作站参考模板落位**：定义独立海外出口 `vps2` (`198.51.100.12`) 物理分流与主机防火墙单向受控隔离基线 |

---

## 二、详细变更与闭环流水（Chronological Details · Newest First）

### UPD-20261114-003
- **标题**：`[UPD][SECURITY][MCP]` StarHub Kit `v1.3.0` 自主 AI 沙箱防火墙预设（`ai-sandbox`）、跨平台四后端（`nftables` / `macOS pf` / `Tailscale ACL` / `Sing-box`）与零依赖原生 `MCP Server` 发布
- **日期**：`2026-11-14`
- **核心交付清单**：
  1. **自主 AI 编程沙箱零横向渗透防火墙预设（`--profile ai-sandbox` · [topology.ai-sandbox.json](../../profiles/topology.ai-sandbox.json)）**：无需任何软路由或虚拟化集群，针对运行 Claude Code、Codex、OpenHands、Docker MCP 容器的开发机与内网环境一键生成防扫段、硬封 `:22` SSH 与 `:5432`/`:6379` 数据库端口策略。
  2. **跨平台四后端编译器（`--target nftables|macos-pf|tailscale-acl|singbox|all`）与碰撞审计（`starhub audit`）**：原生输出 Linux `nftables` 双栈 `inet` 表、macOS `pf` 锚点、Tailscale 官方 `ACL JSON` 及 `Sing-box` 分域 DNS + 手术刀级 QUIC `reject` 规则集。
  3. **零依赖标准 `MCP Server`（`starhub mcp`）**：纯 Python 标准库实现 JSON-RPC 2.0 `stdio` 协议（兼容换行分隔与 `Content-Length` 帧头），支持在 Claude Desktop / Cursor / Windsurf 中直接调用策略编译与拓扑安全体检。

---

### UPD-20261114-002
- **标题**：`[UPD][UX][SECURITY]` StarHub Kit `v1.2.0` 模块化无特权预览（`--only` / `--dry-run`）、逐比特可重现归档（`archive --verify`）、原生 Nix Flake 与 OSPS Baseline L3 完整对齐
- **日期**：`2026-11-14`
- **核心交付清单**：
  1. **模块化无特权标准输出预览（`render --only` & `--dry-run`）**：支持按 `firewall`、`mihomo`、`ai-sandbox`、`lifeline` 独立筛选编译切片，并支持零写盘、无需 Root 权限的 `--dry-run` 终端秒级预览。
  2. **逐比特可重现构建（`archive --verify` / `--verify-file`）与 Nix Flake（[flake.nix](../../flake.nix)）**：固定 PAX 归档头 `mtime=0`、`uid/gid=0` 与字典序排列，实现跨平台 SHA-256 逐字节可复核；内置零依赖 `flake.nix` 支持 `nix run github:Ziqi/starhub-kit` 免克隆单行运行。
  3. **首屏转化漏斗重构与 OpenSSF OSPS Baseline (Level 3) 映射**：精简中英文 `README` 首屏至 4 枚核心徽章，移除首段内部代号认知门槛，嵌入 15 秒纯矢量终端演示 SVG（`assets/terminal-demo.svg`），并在 [SECURITY.md](../../SECURITY.md) 第 6 节补齐 OSPS Baseline L3 八大控制域证据矩阵。

---

### UPD-20261114-001
- **标题**：`[UPD][UX][OSS]` StarHub Kit `v1.1.0` 三级渐进轻量化版本（`Tier 0` 免编译规则包 + `Tier 1` 单网关 `minimal` 模板）与英文协议排障手册上线
- **日期**：`2026-11-14`
- **核心交付清单**：
  1. **Tier 0 免编译黄金规则包（[standalone-mihomo-tailscale-guardrails.yaml](../../scripts/profiles/standalone-mihomo-tailscale-guardrails.yaml)）**：由编译器确定性生成并纳入 `render --check` 零漂移门禁，普通 OpenWrt / Clash Verge + Tailscale 用户无需运行 Python 即可在 30 秒内复制粘贴解决 Fake-IP 回环、DNS 竞速断流与 Apple/Gmail 移动端 QUIC 黑洞。
  2. **Tier 1 单网关轻量版（[profiles/topology.minimal.json](../../profiles/topology.minimal.json) + `./bin/starhub render --profile minimal`）**：支持 `panel`、`home`、`derp`、`workstation`、`vps2/3` 等高阶节点缺省优雅裁剪，仅需「1 台网关 + 1 台电脑 + 1 个出口」即可编译生成精简网关包。
  3. **英文协议与安全深潜手册（[ARCHITECTURE-AND-PLAYBOOK-EN.md](../ARCHITECTURE-AND-PLAYBOOK-EN.md)）**：面向国际社区系统阐述 Tailscale × Fake-IP 防回环、`Section 9a` 精确 QUIC 顺序护栏与云端 AI 沙箱 `B2` 零信任隔离原理。

---

### UPD-20261113-004
- **标题**：`[UPD][SECURITY][OSS]` StarHub Kit `v1.0.3` 获颁 OpenSSF Best Practices `Silver` 银牌（`#16658`）、全量角色化中立重构与移动端 Gmail `Section 9a` 护栏合入
- **日期**：`2026-11-13`
- **核心交付清单**：
  1. **获颁官方 OpenSSF Best Practices `Silver` 银牌认证（`Project #16658`）**：`Passing 67/67 = 100%` + `Silver 55/55 = 100%`（`tiered_percentage = 200%`），在中英文 `README`、[SECURITY.md](../../SECURITY.md) 与 `.github/security-insights.yml` 正式挂载实时徽章与审计证据链。
  2. **全量角色化中立重构与反资产画像升级**：将全部示例节点、智能家居与出口名称统一标准化为无厂商/无个人设备痕迹的中立工程角色（`laptop`、`workstation`、`site-b-node`、`gpu-worker`、`agent_sandbox`、`ip_camera`、`EgressPrimary` 等），并在 `starhub-doctor.py --verify-public-export` 中增加私有设备/厂商标识符动态反泄露扫描。
  3. **移动端 Gmail `Section 9a` 前置 QUIC 规则母版**：补充移动端附件/内嵌图代理（`mail-attachment`、`ci3~6`、`lh3~6.googleusercontent.com`）与 `robinfrontend-pa.googleapis.com` 精确 `UDP/443 REJECT` 规则，显式固化“必须置于广义 Google 代理规则上方”的顺序护栏。

---

### UPD-20261113-003
- **标题**：`[UPD][SECURITY][OSS]` StarHub Kit `v1.0.2` 权威开源证书矩阵（`SLSA Level 3` / `SPDX-2.3` / `REUSE 3.2`）与 OpenSSF Silver 银牌治理基线落位
- **日期**：`2026-11-13`
- **核心交付清单**：
  1. **Sigstore + GitHub OIDC `SLSA Build Level 3` 数字构建证书**：新增 `.github/workflows/attestation.yml`（`actions/attest-build-provenance` `v4.2.2`），自动签发 X.509 密码学溯源证书并发布至仓库 `/attestations` 页面，支持 `gh attestation verify` 验真。
  2. **ISO/IEC 5962 (`SPDX-2.3`) SBOM 与 FSFE `REUSE 3.2` 强校验**：新增零依赖 `scripts/generate-sbom.py` 与标准 `LICENSES/MIT.txt`，并在 CI 接入官方 `fsfe/reuse-action` (`v6.0.0`) 逐文件版权审计。
  3. **OpenSSF Silver（银牌）治理与 `>=80%` 覆盖率硬门禁**：补齐 [GOVERNANCE.md](../../GOVERNANCE.md)（含 DCO 签署与单维护者应急接管预案）、[CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md)、`.github/security-insights.yml`、[SECURITY.md](../../SECURITY.md) 第 5 节架构威胁模型与安全保证论证，以及 `tests/test_coverage_gate.py` 语句覆盖率 CI 硬门禁。

---

### UPD-20261113-002
- **标题**：`[UPD][SECURITY][OSS]` StarHub Kit `v1.0.1` OpenSSF Scorecard 深度供应链加固与签名溯源发布
- **日期**：`2026-11-13`
- **核心加固清单**：
  1. **双模安全不变量模糊测试（`tests/fuzz_starhub_ctl.py`）**：支持原生 Google `atheris` 覆盖率引导模糊测试与零依赖 2,000 轮随机变异测试，每次 PR/Push 自动验证 `STARHUB-BOT-NOSSH` 双栈 `:22 DROP`、分域 DNS 零 `fallback:` 与敏感密钥擦除三大不变量。
  2. **CodeQL `v4.39.3` 40 位 SHA 钉死与 Dependabot 成组原子更新**：消除拆分升级 PR 版本撕裂，配合 `.github/CODEOWNERS` 与分支保护守护默认主干。
  3. **Ed25519 + SLSA/in-toto 发行包签名溯源**：为 Release 归档包提供离线可验签 `.sig` 签名与 `.intoto.jsonl` DSSE 构建溯源清单。

---

### UPD-20261113-001
- **标题**：`[UPD][EGM][OSS]` StarHub Kit `v1.0.0` 首个公开可复现版本发布（`MIT` 协议）
- **日期**：`2026-11-13`
- **核心能力清单**：
  1. **一源声明式编译（`./bin/starhub`）**：从 [STARHUB_GROUND_TRUTH.json](../../STARHUB_GROUND_TRUTH.json) 一键编译双栈白名单防火墙、云端沙箱 `B2` 引导脚本、Mihomo 规则母版与透明网关骨架、摄像头物理断云闸、SSH 配置片段及四路反向救命绳 `systemd` 服务。
  2. **StarHub EGM 3.0 工程治理脚手架**：统一 `AGENTS.md` 软链入口、「1 核 + 6 册 + 2 账」零碎片文档结构、Git `pre-commit` 与 GitHub Actions CI 自动零漂移校验，以及 `--verify-public-export` 数学级反隐私发布扫描门禁。
  3. **预留 `v2.0` 插件化演进接口**：在 [ROADMAP-v2.md](../ROADMAP-v2.md) 冻结 `:3001` 动态探针与 `:8080` `StarHub Home OS v2.0-spec` 硬件驱动插件协议。

---

### WORKSTATION-UPD-20261113-001
- **标题**：`[WORKSTATION][UPD]` 7×24 算力工作站独立出口分流与单向隔离基线模板
- **日期**：`2026-11-13`
- **实施要点**：为高吞吐工作站节点（`workstation` · 示例 `100.64.0.32`）绑定独立 VLESS-Reality 出口 `vps2` (`198.51.100.12`)，通过主机层防火墙阻断向异地私人节点反连并静默丢弃共享局域网入站探测，同时配置 `:2204` 带外救命绳。
