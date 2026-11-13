---
id: INC-YYYYMMDD-NNN
title: 一句话事件标题
severity: P0|P1|P2|P3
component: gateway|mesh|firewall|dashboard|iot|egress
detected: YYYY-MM-DD HH:MM
closed: YYYY-MM-DD HH:MM
duration: <Nh|Nm>
operator: <your-handle>
related_commit: <commit-hash>
related_incidents: []
related_ops: ../ops/STARHUB-LEDGER.md
---

# INC-YYYYMMDD-NNN · <事件标题>

## 0 · 摘要 (TL;DR)

一句话说清：**什么故障 / 真正根因是什么 / 如何根治并防回归**。

## 1 · 时间线

| 时间 | 事件与动作 |
|---|---|
| HH:MM | 告警触发或异常表象发现 |
| HH:MM | 执行 `./bin/starhub doctor` 与抓包定界 |
| HH:MM | 定位根因并实施热修复 |
| HH:MM | 验证恢复并补齐门禁断言 |

## 2 · 根因分析 (`5-Why`)

1. **Why 1**：表面现象是什么？
2. **Why 2**：直接触发机制是什么？
3. **Why 3**：为什么现有保护未能拦截？
4. **Why 4**：设计或配置存在什么盲区？
5. **Why 5（真因）**：体系层面的根本原因。

## 3 · 防回归闭环措施

1. **配置/脚本修复**：更新 [STARHUB_GROUND_TRUTH.json](../../STARHUB_GROUND_TRUTH.json) 并运行 `./bin/starhub render --in-place`。
2. **自动化门禁固化**：将检测规则写入 `scripts/starhub-doctor.py` 对应维度。
3. **台账入库**：同步登记至 [../ops/STARHUB-LEDGER.md](../ops/STARHUB-LEDGER.md)。
