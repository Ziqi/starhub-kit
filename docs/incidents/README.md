# 重大故障深度复盘库 (`docs/incidents/`)

> **定位**：专用于归档 `P0` / `P1` 级基础设施中断、跨洋链路黑洞、路由失步或安全边界事件的 **`5-Why` 根因复盘报告**（常规配置升级与日常小修直接记入 [../ops/STARHUB-LEDGER.md](../ops/STARHUB-LEDGER.md)）。

## 复盘编写规范

1. 复制标准模板 [_template.md](./_template.md) 并命名为 `INC-YYYYMMDD-NNN-<short-slug>.md`。
2. 每份复盘报告必须包含：**一句话摘要（TL;DR）**、**分钟级时间线**、**5-Why 根因链**、**已落地的代码/门禁防回归措施**（优先把人工教训转化为 `starhub-doctor.py` 的自动化断言）。
3. 新增报告后运行 `./bin/starhub doctor --local-docs-only` 验证所有内部链接与锚点 100% 可达。
