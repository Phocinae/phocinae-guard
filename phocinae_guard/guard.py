#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phocinae-guard L0 —— 斑海豹命令行审批门（L0 内核，单文件）。

通用 CLI 形态：面向 Claude Code / Cline / Codex CLI / Crush / dsh / Gemini /
Qwen Code / Kimi Code / OpenHands / Hermes 的 hook / 包装集成。
本次交付只做通用 CLI 形态：stdin 或 --command 收一条 shell 命令
→ 输出判定 + exit code。

三层判定：
  L0    纯离线确定性表（白名单 + 黑名单 + 危险正则）→ 直接 allow / deny；
  L1    L0 不能定夺 → POST /v1/systemone 问两题（noul 放行概率 + score 风险期望）
        → 阈值映射 deny / ask / allow；
  fail-closed  服务器不可用 → 除白名单外一律 deny/ask（PHOCINAE_GUARD_FAIL_CLOSED）。
不变式：只有 allow 类能过门（exit 0）；deny / ask 均非零退出。

exit code: 0=allow  1=deny  2=ask（需人工确认，给 hook 的阻塞态）  3=用法/配置错误
stdout: 一行 JSON（--text 换人读格式）
审计: JSONL 追加（ts + command + cwd + decision + 依据层 + 原因），
      默认 ./phocinae-guard.audit.jsonl。

纯标准库（Python >= 3.8），零第三方依赖。
"""

import argparse
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.request

VERSION = "0.1.0"

EXIT_ALLOW = 0
EXIT_DENY = 1
EXIT_ASK = 2
EXIT_ERROR = 3

BUILTIN_DEFAULTS = {
    "server": "http://127.0.0.1:8155",
    "timeout": 2.0,
    "noul_threshold": 0.65,
    "deny_at": 7.0,
    "ask_at": 4.0,
    "l0_table": "",
    "audit_path": "./phocinae-guard.audit.jsonl",
    "fail_closed": "deny",
    "l1_enabled": False,
    "config": "",
}

ENV_KEYS = {
    "PHOCINAE_GUARD_SERVER": ("server", str),
    "PHOCINAE_GUARD_TIMEOUT": ("timeout", float),
    "PHOCINAE_GUARD_NOUL_THRESHOLD": ("noul_threshold", float),
    "PHOCINAE_GUARD_DENY_AT": ("deny_at", float),
    "PHOCINAE_GUARD_ASK_AT": ("ask_at", float),
    "PHOCINAE_GUARD_TABLE": ("l0_table", str),
    "PHOCINAE_GUARD_AUDIT": ("audit_path", str),
    "PHOCINAE_GUARD_FAIL_CLOSED": ("fail_closed", str),
    "PHOCINAE_GUARD_L1_ENABLED": ("l1_enabled", bool),
    "PHOCINAE_GUARD_CONFIG": ("config", str),
}

CLI_KEY_CASTS = {
    "server": str,
    "timeout": float,
    "noul_threshold": float,
    "deny_at": float,
    "ask_at": float,
    "l0_table": str,
    "audit_path": str,
    "fail_closed": str,
    "l1_enabled": bool,
    "config": str,
}


def _die(msg):
    sys.stderr.write("guard: %s\n" % msg)
    raise SystemExit(EXIT_ERROR)


def load_config(cli_args=None):
    """合并顺序：内置默认 < 配置文件 < 环境变量 < 命令行。"""
    cfg = dict(BUILTIN_DEFAULTS)
    cli_args = cli_args or {}
    conf_path = (cli_args.get("config")
                 or os.environ.get("PHOCINAE_GUARD_CONFIG") or "")
    if conf_path:
        try:
            with open(conf_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except OSError as exc:
            _die("cannot load config %s: %s" % (conf_path, exc))
        except ValueError as exc:
            _die("config %s is not valid JSON: %s" % (conf_path, exc))
        if not isinstance(data, dict):
            _die("config %s must be a JSON object" % conf_path)
        for key in BUILTIN_DEFAULTS:
            if key in data:
                cfg[key] = data[key]
    for env_name, (key, cast) in ENV_KEYS.items():
        raw = os.environ.get(env_name)
        if raw is None or raw == "":
            continue
        try:
            cfg[key] = cast(raw)
        except ValueError:
            _die("bad env %s=%r" % (env_name, raw))
    for key, cast in CLI_KEY_CASTS.items():
        if cli_args.get(key) is not None:
            cfg[key] = cast(cli_args[key])
    if cfg["fail_closed"] not in ("deny", "ask"):
        _die("fail_closed must be 'deny' or 'ask', got %r" % cfg["fail_closed"])
    try:
        cfg["timeout"] = max(0.1, float(cfg["timeout"]))
    except (TypeError, ValueError):
        _die("bad timeout %r" % cfg["timeout"])
    return cfg

# ------------------------------------------------------------------ L0 默认表
DEFAULT_L0 = {
    "whitelist": [
        "ls", "ls -a", "ls -la", "ls -l", "pwd", "whoami", "date", "uname -a",
        "env", "hostname", "id", "echo $?", "which python", "which python3",
        "which node", "which git", "git status", "git status --short", "git diff",
        "git diff --stat", "git log", "git log --oneline", "git log --oneline -10",
        "git show", "git branch", "git branch -a", "git remote -v", "git fetch",
        "git fetch --all", "git stash list", "git tag", "git tag -l",
        "git --version", "python --version", "python3 --version", "pip --version",
        "node --version", "npm --version", "gcc --version", "g++ --version",
    ],
    "whitelist_prefix": [
        "ls", "cat", "head", "tail", "grep", "wc", "sort", "uniq", "du", "df",
        "file", "stat", "echo", "git status", "git diff", "git log", "git show",
        "git fetch", "git remote", "git stash", "git branch", "git tag",
        "git shortlog", "git blame", "python3 -m pytest", "pytest",
        "python -m unittest", "npm test", "npm run lint", "make test",
    ],
    "blacklist": [
        ["rm_system",
         r'(^|[;&|]\s*)rm\s+(-\S+\s+)*(/(\s|$|\*)|\s*(~|\$HOME)(/\*|$)|/(etc|usr|var|boot|bin|sbin|lib|opt|root)(/|$))',
         "rm 删除根目录/家目录/系统路径"],
        ["rm_dot",
         r'(^|[;&|]\s*)rm\s+(-\S+\s+)*\.{1,2}(\s|$)',
         "rm -rf . 或 ..（清空当前/上级目录）"],
        ["sudo_destructive",
         r'(^|[;&|]\s*)sudo\s+(rm|dd|mkfs(\.[a-z0-9]+)?|fdisk|sfdisk|parted|wipefs|shutdown|reboot|poweroff|halt)\b',
         "sudo 破坏性操作"],
        ["pipe_to_sh",
         r'[^;&|]\s*\|\s*(sudo\s+)?(ba|da|k|z|c)?sh\b',
         "命令管道喂给 shell（curl|sh 一类）"],
        ["curl_pipe_sh",
         r'(^|[;&|]\s*)(curl|wget|fetch|lynx|w3m)\b[^;&|]*\|\s*(sudo\s+)?(ba|da|k|z|c)?sh\b',
         "curl/wget 下载即执行"],
        ["git_force_push",
         r'git\s+push\b[^;&|]*(--force(\s|$)|(\s|^)-f(\s|$))',
         "git push --force / -f（--force-with-lease 走 L1）"],
        ["git_push_delete",
         r'git\s+push\b[^;&|]*--delete\b',
         "git push 删除远程分支"],
        ["find_root_delete",
         r'(^|[;&|]\s*)find\s+/(\s|$)[^;&|]*-delete\b',
         "find 从根目录 -delete"],
        ["find_system_delete",
         r'find\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*[^;&|]*-delete\b',
         "find 系统路径 -delete"],
        ["find_exec_rm",
         r'find\b[^;&|]*-exec\s+(sudo\s+)?rm\b',
         "find -exec rm"],
        ["xargs_rm",
         r'xargs\b[^;&|]*\brm\b',
         "xargs 接 rm"],
        ["dd_write_dev",
         r'\bdd\b[^;&|]*\bof=/dev/(sd|hd|vd|nvme|mmcblk|dm-|md|loop|disk)',
         "dd 写块设备"],
        ["mkfs",
         r'(^|[;&|]\s*)(mkfs(\.[a-z0-9]+)?|fdisk|sfdisk|parted|wipefs)\b',
         "格式化/分区工具"],
        ["chmod777",
         r'chmod\s+(-R\s+|--recursive\s+)*77[0-7]\s',
         "chmod 777（含 -R）"],
        ["chown_system",
         r'chown\s+(-\S+\s+)*\S+\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*',
         "chown 系统路径"],
        ["fork_bomb",
         r':\s*\(\s*\)\s*\{',
         "fork bomb :(){ :|:& };:"],
        ["fork_bomb_win",
         r'%0\s*\|\s*%0',
         "fork bomb %0|%0"],
        ["shutdown",
         r'(^|[;&|]\s*)(shutdown|reboot|poweroff|halt)\b',
         "关机/重启"],
        ["crontab_r",
         r'crontab\s+-\S*r\b',
         "crontab -r 清空计划任务"],
        ["write_redirect_system",
         r'\s>>?\s*/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*',
         "重定向覆写系统文件"],
        ["eval_curl",
         r"eval\s+[\"'\`]?\s*\$?\s*\(\s*(curl|wget)\b",
         "eval $(curl ...)"],
        ["source_curl",
         r'(source|\.)\s+<\(\s*(curl|wget)\b',
         "source <(curl ...)"],
        ["sh_c_curl",
         r"(ba)?sh\s+-c\s+[\"']\s*(curl|wget)\b",
         "sh -c 'curl ...'"],
        ["mv_system",
         r'mv\s+(-\S+\s+)*\S+\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*',
         "mv 进系统路径"],
    ],
}

# ------------------------------------------------------------------ L0 表加载与判定
def load_l0_table(path):
    """加载 L0 表（JSON）。缺文件 → 内置默认表；文件各节覆盖内置对应节。"""
    table = {
        "whitelist": set(DEFAULT_L0["whitelist"]),
        "whitelist_prefix": list(DEFAULT_L0["whitelist_prefix"]),
        "blacklist": [list(x) for x in DEFAULT_L0["blacklist"]],
    }
    if not path:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "l0_table.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        sys.stderr.write("guard: L0 table not found (%s); using builtin defaults\n" % path)
        return table
    except OSError as exc:
        _die("cannot read L0 table %s: %s" % (path, exc))
    except ValueError as exc:
        _die("L0 table %s is not valid JSON: %s" % (path, exc))
    if not isinstance(data, dict):
        _die("L0 table %s must be a JSON object" % path)
    if isinstance(data.get("whitelist"), list):
        table["whitelist"] = set(str(x) for x in data["whitelist"])
    if isinstance(data.get("whitelist_prefix"), list):
        table["whitelist_prefix"] = [str(x) for x in data["whitelist_prefix"]]
    if isinstance(data.get("blacklist"), list):
        entries = []
        for item in data["blacklist"]:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                entries.append([str(item[0]), str(item[1]),
                                str(item[2]) if len(item) > 2 else str(item[1])])
        if entries:
            table["blacklist"] = entries
    return table


def normalize(cmd):
    return re.sub(r"\s+", " ", cmd.strip())


def l0_judge(cmd, table):
    cmd = normalize(cmd)
    if not cmd:
        return "deny", "空命令", "L0"
    for name, pattern, note in table["blacklist"]:
        try:
            if re.search(pattern, cmd, re.IGNORECASE):
                return "deny", "L0 黑名单 %s：%s" % (name, note), "L0"
        except re.error as exc:
            sys.stderr.write("guard: bad L0 pattern %s (%s): %s\n"
                             % (name, pattern, exc))
            continue
    if cmd in table["whitelist"]:
        return "allow", "L0 白名单精确命中", "L0"
    for prefix in sorted(table["whitelist_prefix"], key=len, reverse=True):
        if cmd == prefix or cmd.startswith(prefix + " "):
            return "allow", "L0 白名单前缀命中：%s" % prefix, "L0"
    return None, "L0 不能定夺", "L0"

# ------------------------------------------------------------------ L1：/v1/systemone 两问
def systemone_ask(cfg, command, cwd):
    """POST /v1/systemone（P0 扁平协议）：noul(放行 bool) + score(风险层 2-10)。"""
    base = cfg["server"].rstrip("/")
    url = base if base.endswith("/v1/systemone") else base + "/v1/systemone"
    body = {
        "model": "Phocinae-Largha-150M-v1",
        "state": json.dumps({"command": command, "cwd": cwd,
                             "tool": "phocinae-guard/" + VERSION},
                            ensure_ascii=False),
        "questions": [
            {"id": "guard_noul", "type": "noul",
             "instructions": "This command requires human review.",
             "criteria": {
                 "false": "The command is safe to run without human attention.",
                 "true": "A human should inspect this command before it runs."},
             "threshold": float(cfg["noul_threshold"])},
            {"id": "guard_score", "type": "score",
             "instructions": "Assess the risk of the command described in the state."},
        ],
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "User-Agent": "phocinae-guard/" + VERSION},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=cfg["timeout"]) as resp:
        raw = resp.read().decode("utf-8", "replace")
    data = json.loads(raw)
    answers = data.get("answers", {}) if isinstance(data, dict) else {}
    noul_v = answers.get("guard_noul")
    score_v = answers.get("guard_score")
    # 兼容两种应答形状：P0 扁平值 / 旧 mock 嵌套对象。
    noul = noul_v.get("noul") if isinstance(noul_v, dict) else noul_v
    score = score_v.get("score") if isinstance(score_v, dict) else score_v
    if noul is None or score is None:
        raise ValueError("server answer missing guard_noul / guard_score")
    # 扁平 bool → 概率（threshold 已在服务端生效）；数值原样传递。
    noul_p = 1.0 if noul is True else (0.0 if noul is False else float(noul))
    return noul_p, float(score)


def map_l1(noul_p, score, cfg):
    """阈值映射（通道合成取最严格）：
    risk>=deny_at 或 noul=false → deny；risk>=ask_at 或 noul 摇摆 → ask；其余 → allow。
    """
    thr = cfg["noul_threshold"]
    if noul_p <= 1.0 - thr:
        noul_state = "false"
    elif noul_p >= thr:
        noul_state = "true"
    else:
        noul_state = "wavering"
    channels = []
    if score >= cfg["deny_at"]:
        channels.append("deny")
    elif score >= cfg["ask_at"]:
        channels.append("ask")
    else:
        channels.append("allow")
    if noul_state == "false":
        channels.append("deny")
    elif noul_state == "wavering":
        channels.append("ask")
    else:
        channels.append("allow")
    if "deny" in channels:
        decision = "deny"
    elif "ask" in channels:
        decision = "ask"
    else:
        decision = "allow"
    return decision, noul_state

# ------------------------------------------------------------------ 决策编排
def decide(command, cwd, cfg):
    decision, reason, layer = l0_judge(command, cfg["l0_table_data"])
    result = {
        "command": command,
        "cwd": cwd,
        "decision": decision,
        "layer": layer,
        "reason": reason,
        "noul": None,
        "score": None,
        "noul_state": None,
        "thresholds": {
            "noul_threshold": cfg["noul_threshold"],
            "deny_at": cfg["deny_at"],
            "ask_at": cfg["ask_at"],
        },
        "confirm": False,
    }
    if decision is not None:
        return result
    # P0 口径：150M 权重未做过命令审批域校准（实测 L1 信号≈噪声），默认不启用；
    # l1_enabled=true 时才把灰区交给模型（P1 需领域微调 + 标定电池）。
    if not cfg.get("l1_enabled"):
        result["decision"] = cfg["fail_closed"]
        result["layer"] = "fail_closed"
        result["reason"] = ("L1 未启用（l1_enabled=false，模型未经命令审批域校准）"
                            "→ fail-closed=%s" % cfg["fail_closed"])
        return result
    try:
        noul, score = systemone_ask(cfg, command, cwd)
    except Exception as exc:
        # 服务器挂/超时/响应异常 → fail-closed（除白名单外一律 deny/ask）
        result["decision"] = cfg["fail_closed"]
        result["layer"] = "fail_closed"
        result["reason"] = ("L1 服务器不可用或响应异常（%s: %s）→ fail-closed=%s"
                            % (type(exc).__name__, exc, cfg["fail_closed"]))
        return result
    decision, noul_state = map_l1(noul, score, cfg)
    result.update({
        "decision": decision,
        "layer": "L1",
        "reason": ("L1 noul=%.4f（%s，threshold=%.2f） score=%.4f"
                   "（deny>=%g，ask>=%g）→ %s"
                   % (noul, noul_state, cfg["noul_threshold"], score,
                      cfg["deny_at"], cfg["ask_at"], decision)),
        "noul": noul,
        "score": score,
        "noul_state": noul_state,
    })
    return result


# ------------------------------------------------------------------ 审计
def audit(cfg, result):
    path = cfg["audit_path"]
    if not path or str(path).lower() in ("off", "none"):
        return
    rec = {
        "ts": (datetime.datetime.now(datetime.timezone.utc)
               .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"),
        "command": result["command"],
        "cwd": result["cwd"],
        "decision": result["decision"],
        "layer": result["layer"],
        "reason": result["reason"],
        "noul": result.get("noul"),
        "score": result.get("score"),
        "confirm": bool(result.get("confirm")),
    }
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as exc:
        # 审计失败不阻断判定（宁可漏记不误杀）
        sys.stderr.write("guard: audit write failed (%s): %s\n" % (path, exc))


def emit(result, text=False):
    if text:
        print("decision=%s layer=%s" % (result["decision"], result["layer"]))
        print("reason=%s" % result["reason"])
        if result.get("noul") is not None:
            print("noul=%.4f score=%.4f" % (result["noul"], result["score"]))
        return
    out = dict(result)
    out["exit"] = {"allow": EXIT_ALLOW, "deny": EXIT_DENY,
                   "ask": EXIT_ASK}[result["decision"]]
    print(json.dumps(out, ensure_ascii=False))

# ------------------------------------------------------------------ CLI
def build_parser():
    p = argparse.ArgumentParser(
        prog="guard.py",
        description="phocinae-guard L0 命令行审批门：stdin 或 --command 收一条 "
                    "shell 命令 → 判定 + exit code",
    )
    p.add_argument("--command", help="要判定的 shell 命令；缺省从 stdin 读取")
    p.add_argument("--cwd", default=None,
                   help="命令执行工作目录（默认当前目录，用于审计/L1 上下文）")
    p.add_argument("--text", action="store_true",
                   help="人读文本输出（默认一行 JSON）")
    p.add_argument("--confirm", action="store_true",
                   help="人工确认：仅把 ask 升级为 allow；deny 不可覆盖")
    p.add_argument("--config", help="配置文件路径（JSON；env 与命令行覆盖其值）")
    p.add_argument("--server", help="L1 服务基地址（默认 http://127.0.0.1:8155）")
    p.add_argument("--timeout", type=float, help="L1 请求超时秒数（默认 2.0）")
    p.add_argument("--noul-threshold", type=float,
                   help="noul 放行阈值（默认 0.65）")
    p.add_argument("--deny-at", type=float,
                   help="score >= 此值 → deny（默认 7）")
    p.add_argument("--ask-at", type=float,
                   help="score >= 此值且 < deny → ask（默认 4）")
    p.add_argument("--table", dest="l0_table",
                   help="L0 表 JSON 路径（默认同目录 l0_table.json）")
    p.add_argument("--audit", dest="audit_path",
                   help="审计 JSONL 路径（默认 ./phocinae-guard.audit.jsonl；off 禁用）")
    p.add_argument("--fail-closed", choices=("deny", "ask"),
                   help="服务器不可用时的兜底（默认 deny）")
    p.add_argument("--version", action="store_true", help="打印版本")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.version:
        print("phocinae-guard L0 " + VERSION)
        return EXIT_ALLOW
    cfg = load_config(vars(args))
    command = args.command if args.command is not None else sys.stdin.read().strip()
    if not command:
        sys.stderr.write("guard: no command (use --command or pipe via stdin)\n")
        return EXIT_ERROR
    cwd = args.cwd or os.getcwd()
    cfg["l0_table_data"] = load_l0_table(cfg["l0_table"])
    result = decide(command, cwd, cfg)
    if args.confirm:
        result["confirm"] = True
        if result["decision"] == "ask":
            # 人工确认：ask → allow（不变式：deny 永远不可覆盖）
            result["decision"] = "allow"
            result["layer"] = "human_confirm"
            result["reason"] += "；--confirm 人工确认放行"
        elif result["decision"] == "deny":
            result["reason"] += "（--confirm 不能覆盖 deny）"
    audit(cfg, result)
    emit(result, text=args.text)
    return {"allow": EXIT_ALLOW, "deny": EXIT_DENY,
            "ask": EXIT_ASK}[result["decision"]]


if __name__ == "__main__":
    sys.exit(main())
