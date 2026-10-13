#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phocinae-guard · Claude Code PreToolUse hook（纯标准库，零依赖）。

覆盖两族工具调用：

  1) **Shell 命令**（`Bash` 及其别名）→ 交给 guard.py 裁决（L0 表 + 可选 L1）。
  2) **文件写入**（`Write` / `Edit` / `MultiEdit` / `NotebookEdit`）与
     **MCP 工具**（`mcp__*`）→ 由本 hook 的确定性写入层裁决（见下）。

协议（Claude Code command 型 hook）：
  stdin  : PreToolUse 事件 JSON
  stdout : {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                    "permissionDecision": "allow|deny|ask",
                                    "permissionDecisionReason": "..."}}
  exit   : 0 = allow / 无裁决（正常权限流）；2 = deny / ask（阻塞裁决）

为什么写入层是确定性的、不走模型：
  guard.py 的 L0 表是**命令**模式（`rm -rf`、`curl|sh` 一类）。把一段文件内容
  当成 shell 命令行去匹配既没有意义、也会误判。而写入的危险信号本身就是可枚举
  的：改的是哪个路径（凭据/密钥/CI secrets/系统文件）＋写的是哪种操作（覆写
  还是编辑）。这部分完全不需要模型，也不需要服务在跑 —— 装上即生效。

裁决映射（与 guard.py 逐项对齐）：
  guard exit 0 allow → permissionDecision allow   hook exit 0
  guard exit 1 deny  → permissionDecision deny    hook exit 2
  guard exit 2 ask   → permissionDecision ask     hook exit 2（auto 模式也强制弹窗）
  guard exit 3 或子进程异常/超时 → 无 stdout、exit 0 → 落入正常权限流
  （本 hook 从不自动 allow 一条它没能判定的调用。）

服务地址沿用 guard.py 内置默认 http://127.0.0.1:8155，本 hook 不覆盖它；
只显式传 --command / --cwd，其余配置（阈值、fail-closed、L1 开关、审计路径等）
经环境变量透传，用户可自行设定。

审计：guard.py 默认审计路径为 ./phocinae-guard.audit.jsonl（相对当前目录），
本 hook 在用户未设 PHOCINAE_GUARD_AUDIT 时改落到 ~/.phocinae-guard/audit.jsonl，
避免把审计文件散落到每个项目目录；设 PHOCINAE_GUARD_AUDIT=off 可禁用。
"""
import json
import os
import re
import subprocess
import sys

HOOK_EVENT = "PreToolUse"
GUARD_TIMEOUT_S = 15.0  # guard 内部 L1 超时默认 2s；留足余量且远低于 hook 超时 30s

# --------------------------------------------------------------------------
# 工具分类
# --------------------------------------------------------------------------
#: 走 guard.py 的命令型工具。
SHELL_TOOLS = frozenset(["bash", "powershell", "pwsh", "shell", "zsh", "sh", "cmd"])

#: 走本 hook 确定性写入层的文件型工具。
WRITE_TOOLS = frozenset(["write", "edit", "multiedit", "notebookedit", "str_replace_editor"])

#: 文件型工具里，字段名到「这是路径还是内容」的映射。
PATH_FIELDS = ("file_path", "path", "notebook_path", "filename")
CONTENT_FIELDS = ("content", "new_string", "new_str", "new_source", "text")

# --------------------------------------------------------------------------
# 确定性写入层
# --------------------------------------------------------------------------
# 每条：(规则名, 路径正则, 说明)。路径一律转成 POSIX 分隔符、小写后匹配。
# 只判**路径**，不判内容 —— 内容是用户自己要写的东西，按内容拦会频繁误伤。
WRITE_PATH_RULES = [
    ("credential_file",
     r"(^|/)(\.env(\.[a-z0-9_-]+)?|\.netrc|\.pgpass|\.npmrc|\.pypirc|"
     r"credentials(\.json)?|secrets?\.(json|ya?ml|toml)|\.credentials\.ya?ml)$",
     "凭据/密钥文件"),
    ("ssh_material",
     r"(^|/)\.ssh/|(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$|(^|/)known_hosts$",
     "SSH 私钥或授权材料"),
    ("cloud_credentials",
     r"(^|/)\.aws/|(^|/)\.config/gcloud/|(^|/)\.kube/config$|(^|/)\.docker/config\.json$",
     "云平台凭据"),
    ("ci_secrets",
     r"(^|/)\.github/workflows/|(^|/)\.gitlab-ci\.ya?ml$|(^|/)\.circleci/|"
     r"(^|/)Jenkinsfile$|(^|/)\.travis\.ya?ml$",
     "CI 配置（可被用来外泄仓库密钥）"),
    ("shell_startup",
     r"(^|/)(\.bashrc|\.bash_profile|\.zshrc|\.zprofile|\.profile|\.bash_login)$|"
     r"(^|/)Documents/WindowsPowerShell/|(^|/)Documents/PowerShell/",
     "shell 启动脚本（每次开终端都会执行）"),
    ("system_path",
     r"^/(etc|usr|bin|sbin|boot|sys|proc|var/lib)/|^[a-z]:/(windows|program files)",
     "系统路径"),
    ("git_internals",
     r"(^|/)\.git/(config|hooks)(/|$)",
     "Git 内部配置或钩子"),
    ("package_registry_auth",
     r"(^|/)\.yarnrc(\.ya?ml)?$|(^|/)\.gem/credentials$|(^|/)\.pypirc$",
     "包管理器凭据"),
]

#: 路径命中这些规则时直接 deny（其余命中走 ask）。
#:
#: 刻意**不含** `.npmrc` / `.yarnrc`：它们是凭据文件，但也是日常合法编辑对象
#: （换 registry、加 scoped registry）。写成 deny 会把人挡在正常配置之外，而
#: 它们已经被 credential_file 规则覆盖为 ask —— 交人看一眼是这里正确的严格度。
WRITE_DENY_RULES = frozenset(["ssh_material", "cloud_credentials"])

_COMPILED_WRITE_RULES = [
    (name, re.compile(pattern), note) for name, pattern, note in WRITE_PATH_RULES
]


def _norm_path(value):
    """归一化一个路径，供规则匹配。"""
    text = str(value).replace("\\", "/")
    while "//" in text:
        text = text.replace("//", "/")
    return text.lower()


def judge_write(tool_name, tool_input):
    """确定性写入裁决。

    返回 (decision, reason)：
      ("deny", ...)  SSH/云凭据/包管理器凭据被写
      ("ask",  ...)  其他敏感路径（凭据文件、CI 配置、启动脚本、系统路径、.git 内部）
      (None,   "")   不敏感，交回正常权限流

    路径取不到时返回 (None, "")：本层只对**它看得懂的东西**负责，看不懂就交回
    宿主权限流，绝不因为「读不懂」而拦人。
    """
    if not isinstance(tool_input, dict):
        return None, ""
    paths = []
    for field in PATH_FIELDS:
        value = tool_input.get(field)
        if isinstance(value, str) and value.strip():
            paths.append(value)
    # MultiEdit 可能把多个路径放在 edits[] 里
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        for entry in edits:
            if isinstance(entry, dict):
                for field in PATH_FIELDS:
                    value = entry.get(field)
                    if isinstance(value, str) and value.strip():
                        paths.append(value)
    if not paths:
        return None, ""

    findings = []
    worst = None
    for raw in paths:
        normalised = _norm_path(raw)
        for name, pattern, note in _COMPILED_WRITE_RULES:
            if pattern.search(normalised):
                findings.append((name, note, raw))
                if name in WRITE_DENY_RULES and worst != "deny":
                    worst = "deny"
                elif worst is None:
                    worst = "ask"
    if not findings:
        return None, ""

    detail = "；".join(
        "%s（%s）：%s" % (note, name, path) for name, note, path in findings[:3]
    )
    if len(findings) > 3:
        detail += "；另有 %d 处" % (len(findings) - 3)
    if worst == "deny":
        return "deny", "写入受保护路径——%s" % detail
    return "ask", "写入敏感路径——%s" % detail


def _force_utf8_streams():
    """把标准流固定为 UTF-8 + LF。

    hook 的 stdout 是 Claude Code 的协议通道，必须是 UTF-8。文本模式 stdout
    用 locale 编码（Windows 上常是 cp936），中文 permissionDecisionReason
    会被编成 GBK，客户端严格 UTF-8 解码即失败。
    """
    for stream in (sys.stdout, sys.stderr, sys.stdin):
        try:
            stream.reconfigure(encoding="utf-8", newline="\n")
        except (AttributeError, ValueError, OSError):
            pass


def _write_stdout_utf8(text):
    """以 UTF-8 字节写 stdout；没有 .buffer 时退回 os.write(1, ...)。"""
    data = text.encode("utf-8")
    buf = getattr(sys.stdout, "buffer", None)
    if buf is not None:
        buf.write(data)
        buf.flush()
    else:  # pragma: no cover
        os.write(1, data)


def _plugin_root():
    # <plugin-root>/hooks/guard_hook.py → <plugin-root>
    # （官方插件形态把 hooks/ 放在插件根，不在 .claude-plugin/ 里面）
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _guard_py():
    return os.environ.get("PHOCINAE_GUARD_PY") or os.path.join(
        _plugin_root(), "guard.py")


def _run_guard(command, cwd):
    args = [sys.executable, _guard_py(), "--command", command]
    if cwd:
        args += ["--cwd", cwd]
    env = dict(os.environ)
    if not env.get("PHOCINAE_GUARD_AUDIT"):
        audit_dir = os.path.join(os.path.expanduser("~"), ".phocinae-guard")
        try:
            os.makedirs(audit_dir, exist_ok=True)
        except OSError:
            audit_dir = os.getcwd()
        env["PHOCINAE_GUARD_AUDIT"] = os.path.join(audit_dir, "audit.jsonl")
    return subprocess.run(args, capture_output=True, text=True, env=env,
                          timeout=GUARD_TIMEOUT_S)


def _emit(decision, reason):
    # 以 UTF-8 字节写 stdout，而不是 print()：文本模式 stdout 用 locale 编码，
    # 中文 reason 会被编成 GBK（Windows cp936），而 Claude Code 按 UTF-8 读
    # hook 的 stdout —— 实测会在 position 134 抛 UnicodeDecodeError，
    # 于是整条裁决作废，上游把「输出不可解析」当非阻断错误 → 危险命令可能被放行。
    _write_stdout_utf8(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": HOOK_EVENT,
            "permissionDecision": decision,
            "permissionDecisionReason": "phocinae-guard: " + reason,
        },
    }, ensure_ascii=False) + "\n")


def _tool_name(event, tool_input):
    for key in ("tool_name", "toolName", "name"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def main():
    _force_utf8_streams()
    raw = sys.stdin.read()
    if not raw.strip():
        return 0  # 空输入：无裁决，正常权限流
    try:
        event = json.loads(raw)
    except ValueError:
        sys.stderr.write("guard_hook: stdin 非合法 JSON → 落入正常权限流\n")
        return 0
    if not isinstance(event, dict):
        return 0
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return 0

    name = _tool_name(event, tool_input)
    lowered = name.lower()

    # ---- 文件写入族：确定性层，无需服务 ---------------------------------
    if lowered in WRITE_TOOLS:
        decision, reason = judge_write(name, tool_input)
        if decision == "deny":
            _emit("deny", reason)
            return 2
        if decision == "ask":
            _emit("ask", reason)
            return 2
        return 0

    # ---- MCP 工具：名字能看出危险动词时转人工 ---------------------------
    # MCP 工具的参数形状任意，本层只做「名字里带明确破坏性动词」这一条判定；
    # 其余一律交回宿主权限流（看不懂就不拦）。
    if lowered.startswith("mcp__"):
        tail = name.rsplit("__", 1)[-1].lower()
        if re.search(r"(^|_)(delete|remove|drop|destroy|purge|wipe|truncate|"
                     r"revoke|terminate|kill|reset)(_|$)", tail):
            _emit("ask", "MCP 工具的动词具有破坏性（%s）——本层无法读取其参数语义，"
                         "请人工确认" % name)
            return 2
        return 0

    # ---- Shell 命令族：交给 guard.py ------------------------------------
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return 0  # 无可判 shell 命令 → 正常权限流
    cwd = event.get("cwd") or tool_input.get("cwd") or ""
    try:
        proc = _run_guard(command, str(cwd))
    except Exception as exc:
        sys.stderr.write("guard_hook: guard.py 调用失败（%s: %s）→ "
                         "落入正常权限流（本 hook 从不自动 allow 一条它没能判定的调用）\n"
                         % (type(exc).__name__, exc))
        return 0
    decision, reason = None, ""
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("decision"), str):
            decision = obj["decision"]
            reason = str(obj.get("reason") or "")
            break
    if decision == "allow" and proc.returncode == 0:
        _emit("allow", reason or "L0 白名单命中")
        return 0
    if decision == "deny" and proc.returncode == 1:
        _emit("deny", reason or "L0 黑名单命中")
        return 2
    if decision == "ask" and proc.returncode == 2:
        _emit("ask", reason or "灰区命令需人工确认")
        return 2
    sys.stderr.write("guard_hook: guard.py 输出与退出码不一致（exit=%d）→ "
                     "落入正常权限流\n" % proc.returncode)
    return 0


if __name__ == "__main__":
    sys.exit(main())
