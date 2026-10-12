---
name: phocinae-guard
description: 斑海豹命令审批门的行为说明与应对守则。当 phocinae-guard 拦截 Bash 命令、给出 deny/ask 裁决，或需要理解该门的判定逻辑与配置开关时使用；被拒绝后应依据裁决理由更换方案，而不是原样重试。
---

# phocinae-guard 审批门

本机挂着斑海豹命令审批门（PreToolUse(Bash) hook）。每一次 Bash 工具调用都会先经
guard.py 判定，结果以 `permissionDecision` 回到 Claude Code：

| 裁决 | 含义 | 你应该怎么做 |
|------|------|-------------|
| `allow` | L0 白名单命中（只读/常规查询）或 L1 判定安全 | 正常执行 |
| `deny` | L0 黑名单命中（破坏性/危险模式）或风险过高 | **不要原样重试**：读 `permissionDecisionReason`，换成更安全、更小范围的方案（如加 `--dry-run`、限定路径、去掉 `-f`、改用只读查询），或向用户说明风险后请其人工执行 |
| `ask` | 灰区命令，需人工确认（auto 模式下也会强制弹窗） | 向用户说清楚这条命令做什么、风险在哪；用户批准后再继续 |

## 三层判定

1. **L0 确定性表**（纯离线，~0ms）：白名单（精确+前缀）→ allow；危险正则
   （`rm -rf /`、`sudo rm`、`curl|sh`、`git push --force`、`chmod -R 777`、
   fork bomb、写块设备、重定向覆写系统文件等 24 条）→ deny。黑名单先于白名单。
2. **L1 模型裁决**（默认关闭，`PHOCINAE_GUARD_L1_ENABLED=1` 开启）：灰区命令问
   `noul`（是否需人工审）+ `score`（风险 0–10）→ 阈值映射
   （score≥7 → deny；4–6 或 noul 摇摆 → ask；其余 → allow）。
3. **fail-closed**：L1 未开或服务不可用时，灰区一律 deny/ask（默认 deny）——
   这不是门坏了，是宁严勿松。

## 自查清单（写危险命令前先过一遍）

- 会不会删系统/用户数据？`rm` 的目标是否含 `/`、`~`、`$HOME`、`.`、`..`？
- 是不是「下载即执行」？`curl/wget … | sh`、`eval $(curl)`、`sh -c 'curl…'`？
- git 操作会不会改写远程历史？`push --force/-f/--delete`？
- 会不会动权限/属主/块设备？`chmod -R 777`、`chown`、`dd of=/dev/…`、`mkfs`？
- 会不会外发机密？命令是否把 `~/.ssh`、`.env`、密钥文件交给外部服务？
- 会不会递归/批量删除？`find -delete`、`find -exec rm`、`xargs rm`？

有任一条沾边，先按「deny 时怎么办」自己降级方案，再发命令。

## 配置速查（环境变量，hook 透传给 guard.py）

| 环境变量 | 默认 | 作用 |
|---|---|---|
| `PHOCINAE_GUARD_L1_ENABLED` | `0` | 开/关 L1 模型裁决（模型未校准前勿开） |
| `PHOCINAE_GUARD_SERVER` | `http://127.0.0.1:8155` | L1 服务地址 |
| `PHOCINAE_GUARD_FAIL_CLOSED` | `deny` | 灰区兜底：`deny`/`ask` |
| `PHOCINAE_GUARD_AUDIT` | `~/.phocinae-guard/audit.jsonl`（hook 默认） | 审计路径（`off` 禁用） |

## 边界

- 门是**行为护栏**，不是沙箱：L0 正则是确定性启发式，可被混淆手法绕过；高危
  环境请同时保持 Claude Code sandbox 与权限收紧。
- `--confirm` 只升级 ask，deny 永不可覆盖——无法自己给自己放行。
- 门只拦 Bash 工具调用；Write/Edit/MCP 工具不受此 hook 约束。
- 判定与审计记录在 `audit.jsonl`（时间戳+命令+cwd+裁决+依据层），可事后复核。
