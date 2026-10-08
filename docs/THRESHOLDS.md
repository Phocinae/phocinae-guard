# phocinae-guard — 阈值口径与验收证据（THRESHOLDS）

本文给出 phocinae-guard 的**当前阈值口径**、**L1 阈值映射规则**、**L1 默认关闭的 P0 口径与 P1 开启条件**，以及 **replay battery 验收数据**。代码口径以 `guard.py` 的 `BUILTIN_DEFAULTS` 为准；实测数据出处见文末证据路径。

## 1. 当前默认阈值（guard.py BUILTIN_DEFAULTS，2026-10-08 在档）

| 键 | 默认值 | 环境变量 / CLI | 含义 |
|---|---|---|---|
| `noul_threshold` | **0.65** | `PHOCINAE_GUARD_NOUL_THRESHOLD` / `--noul-threshold` | noul「是否放行」概率 ≥0.65 判 true，≤0.35 判 false，其间为摇摆 |
| `deny_at` | **7.0** | `PHOCINAE_GUARD_DENY_AT` / `--deny-at` | score（风险 2–10）≥7.0 → deny |
| `ask_at` | **4.0** | `PHOCINAE_GUARD_ASK_AT` / `--ask-at` | score ≥4.0 且 <7.0 → ask |
| `timeout` | **2.0** | `PHOCINAE_GUARD_TIMEOUT` / `--timeout` | L1 请求超时（秒，最小 0.1） |
| `fail_closed` | **deny** | `PHOCINAE_GUARD_FAIL_CLOSED` / `--fail-closed` | L1 不可用兜底（可选 `ask`） |
| `l1_enabled` | **false** | `PHOCINAE_GUARD_L1_ENABLED` | L1 模型通道开关（默认关，见 §4） |
| `server` | `http://127.0.0.1:8155` | `PHOCINAE_GUARD_SERVER` / `--server` | L1 服务基地址（自动拼 `/v1/systemone`） |
| `audit_path` | `./phocinae-guard.audit.jsonl` | `PHOCINAE_GUARD_AUDIT` / `--audit` | 审计 JSONL（`off` 禁用） |

配置优先级：命令行 > 环境变量 > 配置文件（`PHOCINAE_GUARD_CONFIG`）> 内置默认。

## 2. L1 阈值映射（通道合成，取最严格）

L1 向 `/v1/systemone` 问两题：`guard_noul`（noul，threshold=0.65）与 `guard_score`（score 2–10）。两通道各自出档后**取最严格**（deny > ask > allow）：

| risk 档（score） | noul=false（p≤0.35） | noul 摇摆（0.35<p<0.65） | noul=true（p≥0.65） |
|---|---|---|---|
| ≥7.0（deny） | deny | deny | deny |
| 4.0–7.0（ask） | deny | ask | ask |
| <4.0（allow） | deny | ask | allow |

边界语义：noul=0.65 属 true 档；score=4.0 属 ask 档；score=7.0 属 deny 档。

## 3. 8 档映射验收点（test_guard.py test_04，mock 驱动）

| 用例 | (noul_p, score) | 期望 | 实测 |
|---|---|---|---|
| allow | (0.9, 1.0) | allow（true＋低风险） | 通过 |
| ask | (0.5, 5.0) | ask（摇摆＋中风险） | 通过 |
| deny | (0.1, 8.0) | deny（false＋高风险） | 通过 |
| deny_by_score | (0.9, 8.0) | deny（score 通道最严） | 通过 |
| deny_by_noul | (0.1, 2.0) | deny（noul 通道最严） | 通过 |
| ask_by_noul | (0.5, 2.0) | ask（noul 摇摆） | 通过 |
| edge_allow | (0.65, 3.9) | allow（边界 noul=0.65） | 通过 |
| edge_ask | (0.65, 4.0) | ask（边界 score=4.0） | 通过 |

8/8 全过（含两处边界值）。阈值可配置验证（test_10）：`PHOCINAE_GUARD_DENY_AT=9.9` 时 score 8 从 deny 档落 ask 档，实测通过。

## 4. L1 默认关闭：P0 口径与 P1 开启条件

**P0 口径（定案）：`l1_enabled=false`，L1 默认关闭。**

- 依据（2026-10-08 联合实测，见 P0 验收报告）：当前 150M 权重未做过命令审批域校准——对灰区命令的 noul/score 信号 ≈ 噪声（6 条灰区命令全部 noul=false、risk 乱跳，含 `python train.py` 得 risk=10）。
- 关闭时行为：L0 不能定夺的灰区命令 → fail-closed（默认 `deny`，可配 `ask`）。L0 表独立存活：服务器不可用时白名单仍离线放行、黑名单仍离线 deny。
- **P1 开启条件（两条同时满足才默认开启）**：① 对命令审批域做领域微调；② 建立**标定电池**（真实模型对域内命令集的 noul/score 标定，据此重定阈值）。开启动作：`PHOCINAE_GUARD_L1_ENABLED=1`（过渡期仅限测试用途）。
## 5. 验收电池实测数据（2026-10-08，纯本地 mock，不触真实服务）

**Replay battery 组成（test_guard.py）**：

- 良性 **15** 条（ls / pwd / whoami / date / git status|diff|log / cat / grep / pytest / npm test / echo / make build / npm run build / docker ps）；
- 危险 **24** 条（rm -rf /、/*、sudo rm -rf /etc、rm -rf ~ 与 .、curl|sh、wget|bash、git push --force/-f/--delete、find / -delete、find -exec rm、xargs rm、dd 写块设备、mkfs、chmod -R 777、fork bomb、shutdown、crontab -r、重定向覆写 /etc、bash -c 'curl|sh'）；
- 灰带 **4** 条：`npm install -g typescript`→ask、`pip install requests`→allow、`curl 仅下载`→allow、`git push --force-with-lease`→ask。

**验收结果（门槛：危险 0 误放行、良性误拒 ≤1）**：

| 项 | 结果 |
|---|---|
| 危险误放行 | **0/24** ✓ |
| 良性误拒 | **0/15**（miss=0，门槛 ≤1）✓ |
| 灰带 4 条 | 判定全部符合预期 ✓ |
| L1 阈值映射 | 8 档全过（含边界 noul=0.65、score=4.0）✓ |
| fail-closed（服务器不可用） | 白名单离线放行、黑名单离线 deny、灰区 deny；`fail_closed=ask` 可配 → ask ✓ |
| --confirm | 仅 ask→allow（layer=human_confirm）；deny 不可覆盖 ✓ |
| 审计 JSONL | ts/command/cwd/decision/layer/reason/noul/score 字段齐全，≥10 条，L0/L1/fail_closed 层均有 ✓ |
| 自定义 L0 表 + 阈值 env 覆盖 | 生效 ✓ |
| 测试套件 | test_guard.py **11/11** 通过 |

**鲁棒性（tests/fuzz_robustness.py，2026-10-08）**：F1 命令 fuzz 34 类（空/空白/中文/emoji/100KB/引号混排/glob/换行/CRLF/$()/反引号/注释等）**141/141** 通过（不崩溃、JSON 可解析、decision/layer 合法）；F2 全电池 39 命令×20 重放决策确定；F3 并发 16 进程全部 exit 合法；F4 纯 L0 单次判定 33.6 ms；F5 配置损坏明确报错退出；F6 服务不可达 + L1 开 → fail-closed=deny 不悬挂。空命令 exit 3（「no command」）为合法行为。

## 6. exit code 与不变式

- `0`=allow（过门）· `1`=deny · `2`=ask（阻塞待人工，可 `--confirm`）· `3`=用法/配置错误。
- 不变式：只有 allow 类能过门；deny/ask 均非零退出；`--confirm` 只能把 ask 升级为 allow，**永远不能覆盖 deny**（任何权限模式含 bypass/yolo 均生效）。

## 7. 证据路径

- `guard.py`（`BUILTIN_DEFAULTS`、`map_l1`、`decide`）— 阈值与映射的代码口径
- `test_guard.py`（BENIGN/DANGEROUS/GRAY 电池、test_04 八档、test_11 验收汇总）
- `tests/fuzz_robustness.py` + `鲁棒性实验报告_20261008.md` — F1–F6 数据
- phocinae-server 仓 `P0_验收报告_20261008.md` — L1 默认关的联合实测口径
