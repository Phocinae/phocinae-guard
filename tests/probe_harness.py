#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_harness.py — 定位 test_bypass_regression 里 None.strip() 的真实来源。"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_bypass_regression as T  # noqa: E402

print("REPO =", REPO)
print("GUARD =", getattr(T, "GUARD", "<missing>"))
print("cwd for run_guard =", REPO)
print()

cmd = "rm -rf /"
try:
    code, out, err = T.run_guard(cmd)
    print("code =", repr(code))
    print("out  =", repr(out)[:200])
    print("err  =", repr(err)[:200])
    print("parse =", T.parse(out))
except Exception as exc:
    print("run_guard raised:", type(exc).__name__, exc)

print()
print("--- direct subprocess (mimic run_guard) ---")
env = dict(os.environ)
env["PYTHONIOENCODING"] = "utf-8"
env["PHOCINAE_GUARD_AUDIT"] = os.path.join(T.AUDIT_DIR, "regression.audit.jsonl")
p = subprocess.run([sys.executable, T.GUARD, "--command", cmd],
                   capture_output=True, text=True, env=env, cwd=REPO, timeout=60)
print("rc =", p.returncode)
print("stdout =", repr(p.stdout)[:300])
print("stderr =", repr(p.stderr)[:300])
