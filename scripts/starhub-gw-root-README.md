# starhub-gw (192.0.2.11 + VIP .12 / 100.64.0.11 / LXC 100) 本机运维说明卡

> **版本**：`StarHub Kit v1.0.3` · **权威事实源**：`STARHUB_GROUND_TRUTH.json` + `scripts/profiles/mihomo-shared-guardrails.yaml`

---

## 1. 核心守护组件与路径清单

| 组件 | 本机路径 / Unit | 标准职责说明 |
|---|---|---|
| **Mihomo 主配置** | `/etc/mihomo/config.yaml` (`0600`) | `stack: gvisor` TUN + Fake-IP (`198.18.0.0/16`) + 确定性分域 DNS（`:53 -> :1053`，零 `fallback:` 竞速）+ `Section 9a` Apple/Gmail 精确域名 `UDP/443 REJECT`（前置防遮蔽且零触碰 YouTube Cronet） |
| **双栈防火墙与 `.12` VIP** | `/usr/local/sbin/starhub-ts-mss-clamp.sh` | 挂载 `192.0.2.12/24` 备用 DNS VIP，维护 `:53->:1053` DNAT、`TCPMSS`、`tailscale0 MASQUERADE`、`:7890/:9090` 双栈白名单与 `STARHUB-IPV6-EXIT-GUARD` |
| **带外反向救命绳** | `/etc/systemd/system/starhub-lifeline-gw.service` | 维持至自建中继跳板 `203.0.113.10:2203` 的带外反向 SSH 隧道 |
| **摄像头物理断云闸** | `/root/cam-gate.sh` | 在 `mangle FORWARD` 链一键切断或恢复物联网摄像头（`192.0.2.61`）外部云端推流 |

---

## 2. 无损热加载与脱敏对齐纪律

1. 修改 `/etc/mihomo/config.yaml` 前备份并保持 `chmod 0600`，执行 `/usr/local/bin/mihomo -t -d /etc/mihomo` 语法预检通过后，经 `:9090` `PUT /configs?force=true` 零断流热加载。
2. 变更后将脱敏副本（`secret: ""`）同步回仓库 `scripts/mihomo-config-backup.yaml` 并运行 `./bin/starhub doctor` 验证全绿。
