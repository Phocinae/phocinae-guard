#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phocinae-guard · Claude Code PreToolUse(Bash) 命令 hook（纯标准库，零依赖）。

协议（Claude Code command 型 hook）：
  stdin  : PreToolUse 事件 JSON，待审命令在 tool_input.command
  stdout : {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                    "permissionDecision": "allow|deny|ask",
                                    "permissionDecisionReason": "..."}}
  exit   : 0 = allow / 无裁决（正常权限流）；2 = deny / ask（阻塞裁决）

裁决映射（与 guard.py 逐项对齐）：
  guard exit 0 allow → permissionDecision allow   hook exit 0
  guard exit 1 deny  → permissionDecision deny    hook exit 2
  guard exit 2 ask   → permissionDecision ask     hook exit 2（auto 模式也强制弹窗）
  guard exit 3 或子进程异常/超时 → 无 stdout、exit 0 → 落入正常权限流
  （fail-closed，绝不自动 allow）。

服务地址沿用 guard.py 内置默认 http://127.0.0.1:8155，本 hook 不覆盖它；
只显式传 --command / --cwd，其余配置（阈值、fail-closed、L1 开关、审计路径等）
经环境变量透传，用户可自行设定。

审计：guard.py 默认审计路径为 ./phocinae-guard.audit.jsonl（相对当前目录），
本 hook 在用户未设 PHOCINAE_GUARD_AUDIT 时改落到 ~/.phocinae-guard/audit.jsonl，
避免把审计文件散落到每个项目目录；设 PHOCINAE_GUARD_AUDIT=off 可禁用。
"""
import json
import os
import subprocess
import sys

HOOK_EVENT = "PreToolUse"
GUARD_TIMEOUT_S = 15.0  # guard 内部 L1 超时默认 2s；留足余量且远低于 hook 超时 30s


def _plugin_root():
    # <plugin-root>/.claude-plugin/hooks/guard_hook.py → <plugin-root>
    return os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))


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
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": HOOK_EVENT,
            "permissionDecision": decision,
            "permissionDecisionReason": "phocinae-guard: " + reason,
        },
    }, ensure_ascii=False))


def main():
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
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return 0  # 无可判 shell 命令 → 正常权限流
    cwd = event.get("cwd") or tool_input.get("cwd") or ""
    try:
        proc = _run_guard(command, str(cwd))
    except Exception as exc:
        sys.stderr.write("guard_hook: guard.py 调用失败（%s: %s）→ "
                         "落入正常权限流（fail-closed，不自动 allow）\n"
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
