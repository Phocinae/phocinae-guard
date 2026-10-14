#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phocinae-guard L0 —— 斑海豹命令行审批门（L0 内核，单文件）。

通用 CLI 形态：面向 Claude Code / Cline / Codex CLI / Crush / dsh / Gemini /
Qwen Code / Kimi Code / OpenHands / Hermes 的 hook / 包装集成。
本次交付只做通用 CLI 形态：stdin 或 --command 收一条 shell 命令
→ 输出判定 + exit code。

三层判定：
  L0    纯离线确定性表（白名单 + 黑名单 + 危险正则）→ 直接 allow / deny；
        L0 先对「原串 + 归一化串 + 每个命令段」跑黑名单，再要求**每一段**都
        命中白名单才 allow（`ls\nrm -rf /`、`cat x | "sh"` 一类不再被首 token
        白名单带过）；换行视为命令分隔符，不折叠成空格。
  L1    L0 不能定夺 → POST /v1/systemone 问两题（noul 放行概率 + score 风险期望）
        → 阈值映射 deny / ask / allow；
  fail-closed  服务器不可用 → 除白名单外一律 deny/ask（PHOCINAE_GUARD_FAIL_CLOSED）。
不变式：只有 allow 类能过门（exit 0）；deny / ask 均非零退出。

env 布尔（如 PHOCINAE_GUARD_L1_ENABLED）只认 1/true/yes/on（大小写与首尾空白
无关），其余（含 0/false/off/no）一律按「关」——显式关闭必须真的关。

exit code: 0=allow  1=deny  2=ask（需人工确认，给 hook 的阻塞态）  3=用法/配置错误
stdout: 一行 JSON（--text 换人读格式）
审计: JSONL 追加（ts + command + cwd + decision + 依据层 + 原因），
      默认 ./phocinae-guard.audit.jsonl；写失败默认只告警，
      --strict-audit / PHOCINAE_GUARD_STRICT_AUDIT=1 时改为报错退出。

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

VERSION = "0.1.9"

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

def _die(msg):
    sys.stderr.write("guard: %s\n" % msg)
    raise SystemExit(EXIT_ERROR)


def _env_bool(raw):
    """env 布尔解析：只有 1/true/yes/on（大小写与首尾空白无关）为真。

    与 phocinae-mcp server.py 的 _env_bool 同口径。刻意不用 bool(raw)：
    "0"/"false"/"off"/"no"/"none" 这类显式关闭必须真的关掉；
    未设置/空串/无法识别的取值一律按「关」处理（默认关）。
    """
    if raw is None:
        return False
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


ENV_KEYS = {
    "PHOCINAE_GUARD_SERVER": ("server", str),
    "PHOCINAE_GUARD_TIMEOUT": ("timeout", float),
    "PHOCINAE_GUARD_NOUL_THRESHOLD": ("noul_threshold", float),
    "PHOCINAE_GUARD_DENY_AT": ("deny_at", float),
    "PHOCINAE_GUARD_ASK_AT": ("ask_at", float),
    "PHOCINAE_GUARD_TABLE": ("l0_table", str),
    "PHOCINAE_GUARD_AUDIT": ("audit_path", str),
    "PHOCINAE_GUARD_FAIL_CLOSED": ("fail_closed", str),
    "PHOCINAE_GUARD_L1_ENABLED": ("l1_enabled", _env_bool),
    "PHOCINAE_GUARD_CONFIG": ("config", str),
}

# 审计严格模式（B16）：不放进 ENV_KEYS，因为它不是判定配置的一部分，
# 由 main() 单独解析（默认宽松，`--strict-audit` / env 打开）。
ENV_STRICT_AUDIT = "PHOCINAE_GUARD_STRICT_AUDIT"

CLI_KEY_CASTS = {
    "server": str,
    "timeout": float,
    "noul_threshold": float,
    "deny_at": float,
    "ask_at": float,
    "l0_table": str,
    "audit_path": str,
    "fail_closed": str,
    "l1_enabled": _env_bool,
    "config": str,
}


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
        except (ValueError, TypeError):
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
        "git shortlog", "git blame", "python3 -m pytest", "python -m pytest",
        "pytest", "python -m unittest", "npm test", "npm run lint", "make test",
    ],
    "blacklist": [
        ["rm_system",
         r'(^|[;&|]\s*)rm[ \t]+(-\S+\s+)*(/(\s|$|\*)|\s*(~|\$HOME)(/\*|\s|$)|/(etc|usr|var|boot|bin|sbin|lib|opt|root)(/|$))',
         "rm 删除根目录/家目录/系统路径"],
        ["rm_dot",
         r'(^|[;&|]\s*)rm\s+(-\S+\s+)*\.{1,2}(\s|$)',
         "rm -rf . 或 ..（清空当前/上级目录）"],
        ["sudo_destructive",
         r'(^|[;&|]\s*)sudo\s+(rm|dd|mkfs(\.[a-z0-9]+)?|fdisk|sfdisk|parted|wipefs|shutdown|reboot|poweroff|halt)\b',
         "sudo 破坏性操作"],
        ["pipe_to_sh",
         r'[^;&|]\s*\|\s*(sudo\s+)*(?:"|\')?\\?(ba|da|k|z|c)?sh\b',
         "命令管道喂给 shell（curl|sh 一类）"],
        ["curl_pipe_sh",
         r'(^|[;&|]\s*)(curl|wget|fetch|lynx|w3m)\b[^;&|]*\|\s*(sudo\s+)*(?:"|\')?\\?(ba|da|k|z|c)?sh\b',
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
         r'>>?\s*/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*',
         "重定向覆写系统文件"],
        ["outfile_system",
         r'(^|\s)(-o|--output)\s*=?\s*/(etc|usr|var|boot|bin|sbin|lib|opt|root)(/|\s|$)',
         "输出重定向到系统路径（-o/--output）"],
        ["exfil_stdin",
         r'(^|[;&|]\s*)(curl|wget|fetch)\b[^;&|]*(--data(-binary|-ascii|-raw|-urlencode)?|-d|-T|--upload-file|--post-file)\s*=?\s*@?-(?=\s|$|[;&|])',
         "curl/wget 把 stdin（管道/私钥）外发"],
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
def _flag(obj, key):
    """读 JSON 里的布尔开关；非 bool 的取值按假处理（宁松勿误伤配置解析）。"""
    return obj.get(key) is True


# ----------------------------------------------------------- L0 黑名单的替代改法
# A deny that only says "no" leaves the caller stuck, and the natural next move is
# to retry the same command with cosmetic changes. Each entry below names the
# concrete replacement instead.
#
# INVARIANT, asserted by tests/cc_plugin_self_test.sh and tests/test_remediation.py:
#   every built-in blacklist entry has a hint, every hint has at least one
#   `instead` command, and **no `instead` command trips the blacklist itself**.
# The last clause is the one that matters: a remediation that is itself dangerous
# would turn this table into a way around the gate.
DEFAULT_REMEDIATION = {
    "rm_system": {
        "why": "Deleting a root, home or system path is not recoverable by re-running anything.",
        "instead": [
            "ls -la <path>                      # look first",
            "trash-put <path>                   # move to trash, recoverable",
            "mv <path> <path>.bak               # rename instead of delete",
        ],
        "note": "If you only need to see what would go, use `find <path> -print` — it lists without deleting.",
    },
    "rm_dot": {
        "why": "`rm -rf .` empties the current directory; `.` and `..` are almost never what was meant.",
        "instead": [
            "ls -la                             # confirm where you are",
            "rm -rf ./build ./dist              # name the targets explicitly",
            "trash-put ./build                  # recoverable",
        ],
    },
    "sudo_destructive": {
        "why": "Elevation plus a destructive verb removes the last line of defence.",
        "instead": [
            "sudo -l                            # what is actually permitted",
            "sudo systemctl restart <unit>      # a specific, reversible action",
            "sudo <cmd> --dry-run               # if the tool supports it",
        ],
        "note": "Ask a human before any elevated destructive action; that is what the ask verdict is for.",
    },
    "pipe_to_sh": {
        "why": "Piping into a shell executes whatever arrives, including after a redirect.",
        "instead": [
            "curl -fsSL <url> -o /tmp/x.sh && less /tmp/x.sh   # read it first",
            "curl -fsSL <url> -o /tmp/x.sh && sha256sum /tmp/x.sh",
            "curl -fsSL <url> -o /tmp/x.sh && bash /tmp/x.sh   # then run the file you read",
        ],
    },
    "curl_pipe_sh": {
        "why": "Download-and-execute gives the remote end control of this machine.",
        "instead": [
            "curl -fsSL <url> -o /tmp/install.sh && less /tmp/install.sh",
            "curl -fsSL <url> -o /tmp/install.sh && sha256sum /tmp/install.sh",
            "pipx install <package>             # a package manager instead of a pipe",
        ],
    },
    "git_force_push": {
        "why": "A force push rewrites published history; other clones cannot fast-forward afterwards.",
        "instead": [
            "git push --force-with-lease         # refuses if someone else pushed",
            "git push --force-with-lease --dry-run",
            "git revert <sha> && git push        # forward-fix instead of rewrite",
        ],
        "note": "`--force-with-lease` is deliberately *not* on the block list; it goes to review instead.",
    },
    "git_push_delete": {
        "why": "Deleting a remote branch can discard commits that exist nowhere else.",
        "instead": [
            "git ls-remote --heads origin          # what the remote actually has",
            "git log origin/<branch> --not main   # what would be lost",
            "git branch <branch>-archive origin/<branch>   # keep a local copy first",
        ],
    },
    "find_root_delete": {
        "why": "`find / -delete` walks the whole filesystem and removes matches.",
        "instead": [
            "find <path> -maxdepth 3 -name '<pattern>' -print   # bounded list, no deletion",
            "find <path> -name '<pattern>' -print              # list the full scope",
            "du -sh <path>                                     # how much is involved",
        ],
    },
    "find_system_delete": {
        "why": "Deleting under a system path while walking it can remove live configuration.",
        "instead": [
            "find <system-path> -name '<pattern>' -print   # list, do not delete",
            "ls -la <system-path>                          # inspect the directory",
            "du -sh <system-path>                          # how much is there",
        ],
    },
    "find_exec_rm": {
        "why": "`find -exec rm` deletes inside a walk whose scope is easy to misjudge.",
        "instead": [
            "find <path> <cond> -print       # see the full scope first",
            "find <path> <cond> -ls          # size and timestamps per match",
            "du -sh <path>                   # how much is involved",
        ],
    },
    "xargs_rm": {
        "why": "`xargs rm` deletes whatever the left side produces, including nothing or too much.",
        "instead": [
            "<producer> | xargs -r echo      # echo the arguments first",
            "<producer> | wc -l              # how many targets",
            "<producer> | xargs -r ls -la    # inspect what matched",
        ],
    },
    "dd_write_dev": {
        "why": "Writing to a block device destroys the filesystem on it; the wrong device is one character away.",
        "instead": [
            "lsblk -f                                # confirm the device and its contents",
            "dd if=<image> of=/dev/<dev> status=progress --dry-run   # where supported",
            "dd if=<image> of=/tmp/out.img bs=4M status=progress     # write to a file first",
        ],
    },
    "mkfs": {
        "why": "Formatting erases the target device's contents.",
        "instead": [
            "lsblk -f                        # device, filesystem, label",
            "blkid                           # which filesystems exist right now",
            "cat /proc/partitions            # the kernel's view of the block devices",
        ],
        "note": "`wipefs` is blocked by name even with `-n`: a gate that does not parse flags cannot tell a dry run from the real thing.",
    },
    "chmod777": {
        "why": "World-writable bits on a tree let any local process modify it.",
        "instead": [
            "chmod -R u=rwX,go=rX <path>             # owner writes, others read",
            "chmod -R g+w <path>                     # group write where needed",
            "stat -c '%a %n' <path>                  # inspect before changing",
        ],
    },
    "chown_system": {
        "why": "Changing ownership of system paths can break services and login.",
        "instead": [
            "ls -ld <path>                           # current owner and mode",
            "chown -R --from=<old>:<old> <new>:<new> <path>   # only what still has the old owner",
            "chown <user>:<group> <single-file>      # start from one file",
        ],
    },
    "fork_bomb": {
        "why": "A fork bomb exhausts the process table; recovery usually needs a reboot.",
        "instead": [
            "ulimit -u                               # see the process limit",
            "timeout 5 <command>                     # bound anything recursive",
            "echo '<recursive-command>'              # inspect the text instead of running it",
        ],
    },
    "fork_bomb_win": {
        "why": "The cmd.exe fork bomb spawns shells until the machine stops responding.",
        "instead": [
            "Get-Process | Measure-Object            # current process count",
            "Start-Process <exe> -Wait               # one bounded child",
            "Get-Content .\\script.ps1               # read before running",
        ],
    },
    "shutdown": {
        "why": "Halting or rebooting interrupts everything running on the host, including other people's work.",
        "instead": [
            "who                             # who else is on this host",
            "systemctl list-jobs             # what a restart would interrupt",
            "uptime                          # how long it has been up",
        ],
    },
    "crontab_r": {
        "why": "`crontab -r` deletes the whole schedule with no confirmation and no undo.",
        "instead": [
            "crontab -l > ~/crontab-$(date +%F).bak  # back it up first",
            "crontab -l                              # read it",
            "crontab -e                              # edit the one line you meant",
        ],
    },
    "write_redirect_system": {
        "why": "A redirect truncates the target before anything is written.",
        "instead": [
            "cat <file>                              # read the target first",
            "cp <file> <file>.bak && cat > <file>    # keep a copy",
            "sudo tee -a <file>                      # append rather than truncate",
        ],
    },
    "outfile_system": {
        "why": "Writing tool output into a system path can overwrite configuration.",
        "instead": [
            "<cmd> -o /tmp/out.<ext>                 # write somewhere disposable",
            "<cmd> -o ./out.<ext>                    # or into the project",
            "ls -la <system-path>                    # inspect before writing there",
        ],
    },
    "exfil_stdin": {
        "why": "Sending stdin to a remote host can ship a private key or a credential file off the machine.",
        "instead": [
            "wc -c < <file>                          # how much would leave",
            "sha256sum <file>                        # prove content without moving it",
            "cat <file> | gpg -c > /tmp/x.gpg        # encrypt before any transfer",
        ],
    },
    "eval_curl": {
        "why": "`eval $(curl ...)` runs whatever the remote returns, in this shell.",
        "instead": [
            "curl -fsSL <url> -o /tmp/x.sh && cat /tmp/x.sh   # read it",
            "curl -fsSL <url> -o /tmp/x.sh && bash -n /tmp/x.sh   # syntax-check it",
            "curl -fsSL <url> -o /tmp/x.sh && bash /tmp/x.sh",
        ],
    },
    "source_curl": {
        "why": "`source <(curl ...)` executes the remote response inside the current shell, with its environment.",
        "instead": [
            "curl -fsSL <url> -o /tmp/x.sh && cat /tmp/x.sh",
            "curl -fsSL <url> -o /tmp/x.sh && bash /tmp/x.sh   # a child shell, not this one",
            "curl -fsSL <url> -o /tmp/x.sh && diff /tmp/x.sh <expected>",
        ],
    },
    "sh_c_curl": {
        "why": "`sh -c 'curl ...'` hides the download-and-execute one level deeper.",
        "instead": [
            "curl -fsSL <url> -o /tmp/x.sh && cat /tmp/x.sh",
            "curl -fsSL <url> -o /tmp/x.sh && sha256sum /tmp/x.sh",
            "curl -fsSL <url> -o /tmp/x.sh && bash /tmp/x.sh",
        ],
    },
    "mv_system": {
        "why": "Moving into a system path can displace files a service depends on.",
        "instead": [
            "ls -la <system-path>                    # what is already there",
            "mv <src> /tmp/                         # stage outside the system tree",
            "install -m 0644 <src> <system-path>/<name>   # explicit name and mode",
        ],
    },
}


def load_l0_table(path):
    """加载 L0 表（JSON）。缺文件 → 内置默认表。

    默认为**合并**语义（B13）：文件里的 `whitelist` 追加进内置白名单，
    `whitelist_prefix` 追加，`blacklist` 追加到内置 25 条正则之后——用户加一条
    自定义规则不会再把 `rm -rf /` 一类的内置拦截整节丢掉。

    需要旧版「整节替换」语义时显式声明 `"replace": true`：可写在顶层
    （对所有节生效），也可按节写在 `<节名>_replace`，例如
        {"whitelist": [...], "whitelist_replace": true}     # 只要这一节替换
        {"blacklist": [...], "blacklist_replace": false}    # 显式合并（默认）
        {"replace": true, "blacklist": [...]}               # 顶层：三节都替换
    """
    table = {
        "whitelist": set(DEFAULT_L0["whitelist"]),
        "whitelist_prefix": list(DEFAULT_L0["whitelist_prefix"]),
        "blacklist": [list(x) for x in DEFAULT_L0["blacklist"]],
        # name -> {"why": ..., "instead": [...], "note": ...}
        #
        # This is an *additive* top-level key, deliberately not a fourth element
        # of each blacklist entry: two existing suites assert the entry shape is
        # [name, regex, note], and widening it would silently change a documented
        # protocol for every external table author.
        "remediation": dict(DEFAULT_REMEDIATION),
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
    top_replace = _flag(data, "replace")

    def _replace_section(section):
        # 顶层 replace 或该节的 <节名>_replace 为 true → 替换；否则合并。
        if top_replace:
            return True
        return _flag(data, section + "_replace")

    if isinstance(data.get("whitelist"), list):
        entries = set(str(x) for x in data["whitelist"])
        if _replace_section("whitelist"):
            table["whitelist"] = entries
        else:
            table["whitelist"] |= entries
    if isinstance(data.get("whitelist_prefix"), list):
        entries = [str(x) for x in data["whitelist_prefix"]]
        if _replace_section("whitelist_prefix"):
            table["whitelist_prefix"] = entries
        else:
            merged = list(table["whitelist_prefix"])
            for entry in entries:
                if entry not in merged:
                    merged.append(entry)
            table["whitelist_prefix"] = merged
    if isinstance(data.get("blacklist"), list):
        entries = []
        for item in data["blacklist"]:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                entries.append([str(item[0]), str(item[1]),
                                str(item[2]) if len(item) > 2 else str(item[1])])
        if entries:
            if _replace_section("blacklist"):
                table["blacklist"] = entries
            else:
                # 追加，且不允许自定义条目把内置条目顶掉（保持内置拦截常在）
                existing = set(entry[0] for entry in table["blacklist"])
                table["blacklist"] += [e for e in entries if e[0] not in existing]
    # Remediation hints merge by name; a custom table may add hints for its own
    # entries and may override a built-in hint by reusing its name.
    extra = data.get("remediation")
    if isinstance(extra, dict):
        for name, hint in extra.items():
            table["remediation"][str(name)] = hint
    return table


def remediation_for(table, name):
    """The remediation hint for a blacklist entry, or None.

    Returns a dict with an "instead" list of concrete replacement commands. The
    point is that a deny should not be a dead end: the caller is told what to run
    instead, in a form that can be copied.
    """
    if not name:
        return None
    hint = (table.get("remediation") or {}).get(name)
    if not isinstance(hint, dict):
        return None
    instead = hint.get("instead")
    if not isinstance(instead, list) or not instead:
        return None
    return hint


# 转义换行（行继续）与行内字面 backslash-n：都不是命令分隔符。
_ESC_NL = "\x00esc_nl\x00"
_LIT_NL = "\x00lit_nl\x00"
# 真正的命令分隔符 / 管道符（不含引号内与转义后的字符）。
_SEPARATORS = ("&&", "||", ";", "|")


def split_commands(cmd):
    """把命令行按**未转义、未加引号**的 `&&` `||` `;` `|` 拆成多段。

    用于「逐段过黑名单」：`ls ; \\rm -rf /` 的第二段会被单独看到。
    引号内的分隔符（`echo "a|b"`）与反斜杠转义的分隔符保持原样，
    避免把合法命令误判成多段。
    """
    segs = []
    buf = []
    quote = None
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if quote:
            # 引号内：只有配对的引号能关闭引用，其余原样保留
            if ch == quote:
                quote = None
            buf.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\":
            # 转义：字符原样保留，且不参与分隔符识别（`rm\ -rf` / `a\|b`）
            if i + 1 < n:
                buf.append(ch)
                buf.append(cmd[i + 1])
                i += 2
            else:
                buf.append(ch)
                i += 1
            continue
        sep = None
        for cand in _SEPARATORS:
            if cmd.startswith(cand, i):
                sep = cand
                break
        if sep:
            segs.append("".join(buf))
            buf = []
            i += len(sep)
            continue
        buf.append(ch)
        i += 1
    segs.append("".join(buf))
    return [seg.strip() for seg in segs if seg.strip()]


def _split_command_segments(cmd):
    """按段返回命令：新行（normalize 后为 ` ; `）与 `;`/`&&`/`||`/`|` 均分段。"""
    return split_commands(cmd)


def _map_unquoted(text, fn, pair_escapes=True):
    """对 `text` 中**引号外**的字符跑 `fn(ch)`，引号内原样保留。

    反斜杠转义对（`\\x`）整体保留，避免把被转义的引号当成引号边界。
    """
    out = []
    quote = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
            out.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if pair_escapes and ch == "\\" and i + 1 < n:
            out.append(ch)
            out.append(text[i + 1])
            i += 2
            continue
        out.append(fn(ch))
        i += 1
    return "".join(out)


def normalize(cmd):
    """归一化**但不破坏命令边界**：
      - 转义换行（`\\` + 换行）与字面 `\\n` 保留，不作为分隔符；
      - `\\r\\n` / `\\n` / `\\r` → ` ; `（换行 = 新命令，不是普通空白）；
      - 引号外、未转义的制表符也视为命令分隔 → ` ; `（`ls\\trm -rf /` 是两条
        命令，旧实现把它折叠成 `ls rm -rf /`，正好绕开锚定 `(^|[;&|]\\s*)` 的规则）；
      - 其余行内空白（空格/多空格）折叠为一个空格。

    注意：换行若折叠成空格，`ls\\nrm -rf /` 会变成 `ls rm -rf /`，黑名单里
    锚定 `(^|[;&|]\\s*)` 的 `rm` 规则就再也匹配不上——旧实现正是这样被绕过的。
    """
    if not isinstance(cmd, str):
        cmd = str(cmd)
    cmd = (cmd.replace("\x00", "")
              .replace("\\\r\n", _ESC_NL)
              .replace("\\\n", _ESC_NL)
              .replace("\\n", _LIT_NL))
    cmd = re.sub(r"\r\n|\r|\n", " ; ", cmd)
    cmd = _map_unquoted(cmd, lambda ch: " ; " if ch == "\t" else ch)
    text = re.sub(r"[ \f\v]+", " ", cmd).strip()
    return text.replace(_ESC_NL, "\\\n").replace(_LIT_NL, "\\n")


def _blacklist_candidates(cmd, segs):
    """黑名单要检查的候选串：原串 + 归一化串 + 每一段（去前导 `\\`）。"""
    out = [cmd]
    norm = normalize(cmd)
    if norm and norm not in out:
        out.append(norm)
    for seg in segs or []:
        out.append(seg)
        # shell 里 `\\rm` 与 `rm` 等价（还有 `\\\\rm`），去掉前导转义再查一遍
        stripped = seg
        while stripped.startswith("\\"):
            stripped = stripped[1:]
        if stripped and stripped not in out:
            out.append(stripped)
    return out


def _snippet(text, limit=160):
    """reason 里回显命中片段时截断，避免 100KB 命令把审计/日志撑爆。"""
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    if len(text) <= limit:
        return text
    return text[:limit] + "…(%d 字符已截断)" % (len(text) - limit)


def _blacklist_hit(table, candidates):
    for name, pattern, note in table["blacklist"]:
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            sys.stderr.write("guard: bad L0 pattern %s (%s): %s\n"
                             % (name, pattern, exc))
            continue
        for text in candidates:
            if text and rx.search(text):
                return name, note, text
    return None


def _segment_hit(text, table):
    """单段是否命中白名单（精确或前缀）。命中返回理由，否则 None。"""
    if text in table["whitelist"]:
        return "L0 白名单精确命中"
    for prefix in sorted(table["whitelist_prefix"], key=len, reverse=True):
        if text == prefix or text.startswith(prefix + " "):
            return "L0 白名单前缀命中：%s" % prefix
    return None


def l0_judge(cmd, table):
    """L0 判定：黑名单（全串 + 逐段）优先，之后白名单**逐段**校验。

    旧实现只看归一化后的整串且只匹配首 token，于是
    `ls\\nrm -rf /`、`cat x | "sh"`、`echo pwned>/etc/passwd` 都会被
    首 token 白名单放行。现在：
      1) 黑名单同时对原串、归一化串、每一段（含去前导 `\\`）跑；
      2) 只有在黑名单全不中的前提下才看白名单；
      3) 白名单要求**每一段**都命中——第 1 段命中不能给第 2 段背书。

    黑名单命中时，返回四元组，第 4 项是规则名，供调用方取替代改法
    （remediation）；其余分支返回 (decision, reason, layer, None)。
    """
    segs = _split_command_segments(normalize(cmd))
    if not segs:
        return "deny", "空命令", "L0", None
    hit = _blacklist_hit(table, _blacklist_candidates(cmd, segs))
    if hit is not None:
        name, note, matched = hit
        return ("deny", "L0 黑名单 %s：%s（命中：%s）"
                % (name, note, _snippet(matched)), "L0", name)
    for seg in segs:
        reason = _segment_hit(seg, table)
        if reason is None:
            return None, "L0 不能定夺", "L0", None
    return "allow", "L0 白名单逐段命中（%s）" % segs[0], "L0", None

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
    decision, reason, layer, rule_name = l0_judge(command, cfg["l0_table_data"])
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
    # A deny should not be a dead end. When the block came from a named L0 rule,
    # attach the concrete alternatives so the caller can act instead of retrying
    # the same command with cosmetic changes.
    if decision == "deny" and rule_name:
        hint = remediation_for(cfg["l0_table_data"], rule_name)
        if hint:
            result["remediation"] = {
                "rule": rule_name,
                "why": hint.get("why"),
                "instead": list(hint.get("instead") or []),
                "note": hint.get("note"),
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
def audit(cfg, result, strict=False):
    """写审计 JSONL。

    默认宽松：写失败只在 stderr 告警，判定不变（宁可漏记不误杀）。
    strict=True（`--strict-audit` / PHOCINAE_GUARD_STRICT_AUDIT=1）时：
    审计写不下去 → 直接报错退出（exit 3），避免「以为在记，其实没记」。
    """
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
        # newline=""：JSONL 每条记录固定以 \n 结尾，跨平台都能逐行解析
        with open(path, "a", encoding="utf-8", newline="") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as exc:
        if strict:
            _die("audit write failed (%s): %s（--strict-audit 下审计失败即失败）"
                 % (path, exc))
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
    p.add_argument("--l1-enabled", dest="l1_enabled", action="store_true",
                   default=None,
                   help="启用 L1（灰区交 /v1/systemone 裁决；默认关，"
                        "env PHOCINAE_GUARD_L1_ENABLED=1/true/yes/on）")
    p.add_argument("--strict-audit", dest="strict_audit", action="store_true",
                   default=None,
                   help="审计写失败即报错退出（默认只告警；"
                        "env PHOCINAE_GUARD_STRICT_AUDIT）")
    p.add_argument("--version", action="store_true", help="打印版本")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.version:
        print("phocinae-guard L0 " + VERSION)
        return EXIT_ALLOW
    cfg = load_config(vars(args))
    strict_audit = (args.strict_audit if args.strict_audit is not None
                    else _env_bool(os.environ.get(ENV_STRICT_AUDIT)))
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
    audit(cfg, result, strict=strict_audit)
    emit(result, text=args.text)
    return {"allow": EXIT_ALLOW, "deny": EXIT_DENY,
            "ask": EXIT_ASK}[result["decision"]]


if __name__ == "__main__":
    sys.exit(main())
