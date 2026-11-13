# 06 · AI 接力开发与多智能体协同宪章 (Multi-Agent Governance & Handoff Playbook)

> **版本**：`StarHub Kit v1.0.2`  
> **关联手册**：[AGENTS.md](../AGENTS.md) · [02-日常运维与变更升级.md](./02-日常运维与变更升级.md) · [SECURITY.md](../SECURITY.md)

---

## 1. 多智能体协同架构：为什么统一软链至 `AGENTS.md`？

在现代基础设施运维中，工程师往往交替使用多种终端与云端 AI 编程代理。若仓库内同时维护独立的 `AGENTS.md`、`CLAUDE.md` 与 `GROK.md`，数周后必然出现指令版本分裂与旧 IP 幻觉。

**星枢 EGM 3.0 强制规范**：
- 全仓仅保留唯一根级正文 [AGENTS.md](../AGENTS.md)，`CLAUDE.md` 与 `GROK.md` 必须为指向 `AGENTS.md` 的相对路径 POSIX 软链接（由 `DIM1-DOC-WHITELIST` 每次提交自动核验）；
- 任何 AI 会话启动后的第一步操作固定为读取 `AGENTS.md` 与 `STARHUB_GROUND_TRUTH.json`，随后运行 `./bin/starhub doctor --local-docs-only` 对齐基线。

---

## 2. 桌面主控 CLI + `tmux` 与移动端 SSH/Mosh 无缝接力范式

1. **会话持久化**：在主控机（`laptop` 或 `panel`）统一在命名 `tmux` 会话（如 `tmux new -As starhub-ops`）内启动 AI 编程 CLI，出门在外可通过移动端 SSH/Mosh 客户端经 Tailscale（示例 `100.64.0.31`）随时重连同一终端上下文审批变更计划。
2. **远程会话代理免门禁加固**：部分桌面操作系统对非 GUI 远程 SSH/tmux 会话下的第三方二进制实施本地网络隐私拦截；通过系统原生豁免二进制 `/usr/bin/ssh -N -L 127.0.0.1:17890:<gw_ip>:7890` 建立本地回环代理口，可让所有 CLI 工具 100% 免弹窗稳定联网。

---

## 3. 云端沙箱 Agent（`B2` 受限访客模式）安全接入模板

当需要让运行在公有云临时容器中的 AI Agent 自主读取 `:3001` 看板健康度或触发 `:8080` 非破坏性家居动作时：

1. **沙箱侧**：传入短期受限 `TS_AUTHKEY` 运行 [scripts/agent-tailscale-bootstrap.sh](../scripts/agent-tailscale-bootstrap.sh)，脚本自动基于容器实例 ID 创建独立 `/tmp/tailscale-<id>` 状态目录（防止多并发沙箱共用状态导致 `NodeKey` 抢占掉线），并在 `127.0.0.1:1055` 启动用户态代理。
2. **内网侧**：由 `./bin/starhub render` 生成的双栈防火墙自动放行沙箱对 `:3001` 与 `:8080` 的 HTTP 请求，同时通过 `STARHUB-BOT-NOSSH` / `STARHUB-BOT-NOSSH6` 硬丢弃一切 `:22` SSH 握手包，从物理层杜绝云端沙箱登录内网主机 Shell。

---

## 4. 新会话开场标准 Prompt 模板

```text
请先依次阅读仓库根目录的 AGENTS.md 与 STARHUB_GROUND_TRUTH.json，严守星枢十大铁律与文件白名单纪律。
在修改任何配置或文档前：
1. 先输出结构化实施计划（列明拟改文件、不触碰范围与风险回滚方案）并等待人工 Approve；
2. 涉及节点/IP/防火墙变更时，一律修改 STARHUB_GROUND_TRUTH.json 后通过 ./bin/starhub render 确定性编译生成；
3. 收尾时更新 docs/ops/STARHUB-LEDGER.md 并运行 ./bin/starhub doctor 验证 FAIL=0。
```
