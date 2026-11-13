# StarHub Kit 全域统一变更与故障闭环主台账 (`STARHUB-LEDGER`)

> **版本**：`StarHub Kit v1.0.0`  
> **设计原则**：告别在多份零散文档中重复抄写流水的传统做法，一切**架构演进 `[UPD]`**、**缺陷根因闭环 `[BUGFIX]`** 与**算力工作站专项变更 `[STUDIO]`** 均按时间倒序（Append-Only，最新在最上方）统一追加于本账本。  
> **关联索引**：
> - 静态机器事实源（SSOT）：[STARHUB_GROUND_TRUTH.json](../../STARHUB_GROUND_TRUTH.json) · [mihomo-shared-guardrails.yaml](../../scripts/profiles/mihomo-shared-guardrails.yaml)
> - 重大事故 `5-Why` 复盘库：[docs/incidents/README.md](../incidents/README.md)
> - 按 `[STUDIO]` 标签单独导出算力工作站变更摘要：`./bin/starhub export-studio`

---

## 一、快速检索总表（Master Index）

| 条目 ID | 标签 | 日期 | 涉及模块 | 一句话摘要 |
|---|---|---|---|---|
| [UPD-20261113-001](#upd-20261113-001) | `[UPD][EGM][OSS]` | 2026-11-13 | `starhub-ctl` / `starhub-doctor` / `docs` | **StarHub Kit `v1.0.0` 首个净室开源版发布**：落地零依赖声明式拓扑编译器、`100.x + 4via6` 零撞段组网蓝图、确定性分域 DNS 与 Apple/Gmail 精确 QUIC 治理、四路救命绳、摄像头断云闸及 EGM 3.0 八维门禁 |
| [STUDIO-UPD-20261113-001](#studio-upd-20261113-001) | `[STUDIO][UPD]` | 2026-11-13 | `studio` (`100.64.0.132`) | **算力工作站参考模板落位**：定义独立海外出口 `vps2` (`198.51.100.12`) 物理分流与主机防火墙单向受控隔离基线 |

---

## 二、详细变更与闭环流水（Chronological Details · Newest First）

### UPD-20261113-001
- **标题**：`[UPD][EGM][OSS]` StarHub Kit `v1.0.0` 首个公开可复现版本发布（`MIT` 协议）
- **日期**：`2026-11-13`
- **核心能力清单**：
  1. **一源声明式编译（`./bin/starhub`）**：从 [STARHUB_GROUND_TRUTH.json](../../STARHUB_GROUND_TRUTH.json) 一键编译双栈白名单防火墙、云端沙箱 `B2` 引导脚本、Mihomo 规则母版与透明网关骨架、摄像头物理断云闸、SSH 配置片段及四路反向救命绳 `systemd` 服务。
  2. **StarHub EGM 3.0 工程治理脚手架**：统一 `AGENTS.md` 软链入口、「1 核 + 6 册 + 2 账」零碎片文档结构、Git `pre-commit` 与 GitHub Actions CI 自动零漂移校验，以及 `--verify-public-export` 数学级反隐私发布扫描门禁。
  3. **预留 `v2.0` 插件化演进接口**：在 [ROADMAP-v2.md](../ROADMAP-v2.md) 冻结 `:3001` 动态探针与 `:8080` `StarHub Home OS v2.0-spec` 硬件驱动插件协议。

---

### STUDIO-UPD-20261113-001
- **标题**：`[STUDIO][UPD]` 7×24 算力工作站独立出口分流与单向隔离基线模板
- **日期**：`2026-11-13`
- **实施要点**：为高吞吐工作站节点（`studio` · 示例 `100.64.0.132`）绑定独立 VLESS-Reality 出口 `vps2` (`198.51.100.12`)，通过主机层防火墙阻断向异地私人节点反连并静默丢弃共享局域网入站探测，同时配置 `:2204` 带外救命绳。
