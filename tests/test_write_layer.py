# -*- coding: utf-8 -*-
"""Write-layer checks: the hook must judge file writes deterministically.

Before this layer existed the hook read only ``tool_input.command``. Widening the
matcher without widening the hook would have made every ``Write``/``Edit`` call
fall through the "no command" branch and return *no decision* -- which Claude
Code treats as "continue to the normal permission flow", i.e. the gate would
silently not exist for exactly the tools it had just been extended to cover.

These checks drive the real hook over stdin, so they test the wiring, not just
the predicate.

    python tests/test_write_layer.py
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "hooks", "guard_hook.py")

_passed = 0
_failed = []


def check(label, condition, detail=""):
    global _passed
    if condition:
        _passed += 1
        return True
    _failed.append((label, detail))
    return False


def run_hook(event):
    """Run the real hook over stdin and return (exit_code, decision, reason)."""
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.setdefault("PHOCINAE_GUARD_AUDIT", "off")
    proc = subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps(event, ensure_ascii=False).encode("utf-8"),
        capture_output=True,
        env=env,
    )
    decision, reason = None, ""
    out = proc.stdout.decode("utf-8", "replace").strip()
    if out:
        try:
            payload = json.loads(out)
            hook_out = payload.get("hookSpecificOutput") or {}
            decision = hook_out.get("permissionDecision")
            reason = hook_out.get("permissionDecisionReason") or ""
        except ValueError:
            decision = None
    return proc.returncode, decision, reason


def write_event(path, tool="Write", content="hello"):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"file_path": path, "content": content},
        "cwd": os.getcwd(),
    }


def main():
    stream = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    # -- deny: material that must never be written silently --------------
    #
    # The line drawn here is *irreplaceable identity* versus *revocable token*.
    # An SSH private key or a cloud credential file is the identity itself; a
    # registry token is revocable and its config file is edited in the ordinary
    # course of work, so those go to `ask` (see the ask list below).
    deny_cases = [
        os.path.join("home", "user", ".ssh", "id_rsa"),
        os.path.join("home", "user", ".aws", "credentials"),
        os.path.join("home", "user", ".kube", "config"),
    ]
    for path in deny_cases:
        code, decision, reason = run_hook(write_event(path))
        check(
            "W1 deny for %s" % path,
            code == 2 and decision == "deny",
            "exit=%s decision=%s reason=%s" % (code, decision, reason[:80]),
        )

    # -- ask: sensitive but not automatically fatal ----------------------
    ask_cases = [
        os.path.join("proj", ".env"),
        os.path.join("proj", ".env.production"),
        os.path.join("proj", ".github", "workflows", "ci.yml"),
        os.path.join("home", "user", ".bashrc"),
        "/etc/hosts",
        os.path.join("proj", ".git", "config"),
        os.path.join("proj", ".gitlab-ci.yml"),
        os.path.join("home", "user", ".npmrc"),
        os.path.join("home", "user", ".pypirc"),
        os.path.join("home", "user", ".gem", "credentials"),
    ]
    for path in ask_cases:
        code, decision, reason = run_hook(write_event(path))
        check(
            "W2 ask for %s" % path,
            code == 2 and decision == "ask",
            "exit=%s decision=%s reason=%s" % (code, decision, reason[:80]),
        )

    # -- no decision: ordinary files must be untouched -------------------
    quiet_cases = [
        os.path.join("proj", "src", "main.py"),
        os.path.join("proj", "README.md"),
        os.path.join("proj", "tests", "test_thing.py"),
    ]
    for path in quiet_cases:
        code, decision, reason = run_hook(write_event(path))
        check(
            "W3 no decision for %s" % path,
            code == 0 and decision is None,
            "exit=%s decision=%s" % (code, decision),
        )

    # -- Edit tool carries new_string, not content -----------------------
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": os.path.join("home", "user", ".ssh", "known_hosts"),
            "old_string": "a",
            "new_string": "b",
        },
    }
    code, decision, _reason = run_hook(event)
    check("W4 Edit is judged too", code == 2 and decision == "deny", "exit=%s decision=%s" % (code, decision))

    # -- MultiEdit carries a list of edits -------------------------------
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": os.path.join("proj", "src", "a.py"),
            "edits": [{"file_path": os.path.join("proj", ".env"), "new_string": "x"}],
        },
    }
    code, decision, _reason = run_hook(event)
    check("W5 MultiEdit edits[] are scanned", code == 2 and decision == "ask", "exit=%s decision=%s" % (code, decision))

    # -- MCP destructive verb -> ask, everything else -> silence ---------
    for name, expected in (
        ("mcp__filesystem__delete_file", "ask"),
        ("mcp__db__drop_table", "ask"),
        ("mcp__filesystem__read_file", None),
        ("mcp__search__query", None),
    ):
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": name,
            "tool_input": {"path": os.path.join("proj", "x.txt")},
        }
        code, decision, _reason = run_hook(event)
        check(
            "W6 MCP %s -> %s" % (name, expected or "no decision"),
            decision == expected and (code == 2 if expected else code == 0),
            "exit=%s decision=%s" % (code, decision),
        )

    # -- a write with no usable path must not be blocked ------------------
    event = {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"content": "x"}}
    code, decision, _reason = run_hook(event)
    check("W7 a write with no path is left to the host", code == 0 and decision is None, "exit=%s decision=%s" % (code, decision))

    # -- Windows separators must be normalised ---------------------------
    code, decision, _reason = run_hook(write_event(r"C:\Users\me\.ssh\id_ed25519"))
    check("W8 backslash paths are normalised", code == 2 and decision == "deny", "exit=%s decision=%s" % (code, decision))

    # -- the shell branch must still work --------------------------------
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
    }
    code, decision, _reason = run_hook(event)
    check("W9 the shell branch still denies rm -rf /", code == 2 and decision == "deny", "exit=%s decision=%s" % (code, decision))

    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
    }
    code, decision, _reason = run_hook(event)
    check("W10 the shell branch still allows git status", code == 0 and decision == "allow", "exit=%s decision=%s" % (code, decision))

    # -- stdout must be valid UTF-8 (the GBK regression) -----------------
    event = write_event(os.path.join("proj", ".env"))
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PHOCINAE_GUARD_AUDIT"] = "off"
    proc = subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps(event, ensure_ascii=False).encode("utf-8"),
        capture_output=True,
        env=env,
    )
    try:
        proc.stdout.decode("utf-8")
        decoded = True
    except UnicodeDecodeError:
        decoded = False
    check("W11 stdout is valid UTF-8 (the GBK regression)", decoded)

    for label, detail in _failed:
        stream.write("  FAIL %s\n" % label)
        if detail:
            stream.write("       %s\n" % detail)
    stream.write("test_write_layer             PASS=%d FAIL=%d SKIP=0\n" % (_passed, len(_failed)))
    if _passed == 0:
        stream.write("FAIL: nothing was verified\n")
        return 1
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
