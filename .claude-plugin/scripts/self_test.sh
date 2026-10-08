#!/usr/bin/env bash
# phocinae-guard · Claude Code 插件自测（纯本地、纯 CPU，不起真实模型服务）
#
# 覆盖：
#   1) plugin.json / hooks.json 均可解析 + 关键结构断言；
#   2) guard.py 直连：良性 → exit 0，危险 → exit 1，灰区（L1 默认关闭）→ fail-closed；
#   3) hook 链路（Claude Code PreToolUse JSON 协议）：良性 → exit 0 + allow，
#      危险 → exit 2 + deny，灰区 → exit 2 + deny；
#   4) L1 端到端：本地 mock 起在 127.0.0.1:8155（guard 内置默认 server，hook 不覆盖），
#      PHOCINAE_GUARD_L1_ENABLED=1 时灰区走阈值映射（npm -g → ask，pip → allow）；
#      8155 被真实服务占用/绑定失败 → 该节 SKIP（不算失败）；
#   5) 审计 JSONL 落盘校验。
#
# 用法：bash .claude-plugin/scripts/self_test.sh（退出码 0 = 全绿）
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLUGIN_JSON="$ROOT/.claude-plugin/plugin.json"
HOOKS_JSON="$ROOT/.claude-plugin/hooks/hooks.json"
HOOK="$ROOT/.claude-plugin/hooks/guard_hook.py"
GUARD="$ROOT/guard.py"
PY="${PYTHON:-python3}"

TMP="$(mktemp -d)"
export PHOCINAE_GUARD_AUDIT="$TMP/audit.jsonl"
unset PHOCINAE_GUARD_L1_ENABLED PHOCINAE_GUARD_SERVER PHOCINAE_GUARD_FAIL_CLOSED

MOCK_PID=""
cleanup() {
  if [ -n "$MOCK_PID" ]; then
    kill "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf 'SKIP  %s\n' "$1"; }

echo "== phocinae-guard Claude Code 插件自测（root=$ROOT）=="

# ---------------------------------------------------------------- 1) JSON 解析
if "$PY" -c 'import json,sys; json.load(open(sys.argv[1],encoding="utf-8"))' \
    "$PLUGIN_JSON" 2>/dev/null; then
  ok "plugin.json 可解析"
else
  bad "plugin.json 解析失败"
fi
if "$PY" -c 'import json,sys; json.load(open(sys.argv[1],encoding="utf-8"))' \
    "$HOOKS_JSON" 2>/dev/null; then
  ok "hooks.json 可解析"
else
  bad "hooks.json 解析失败"
fi

if "$PY" - "$PLUGIN_JSON" <<'PYEOF'
import json, sys
p = json.load(open(sys.argv[1], encoding="utf-8"))
assert p["name"] == "phocinae-guard", "name 不符"
assert p["version"] == "0.1.0", "version 不符"
assert p["license"] == "Apache-2.0", "license 不符"
assert isinstance(p.get("author"), dict) and p["author"].get("name"), "author 缺失"
assert p.get("hooks", "").endswith("hooks.json"), "hooks 组件声明缺失"
assert p.get("skills", "").startswith("./"), "skills 组件声明缺失"
print("ok")
PYEOF
then
  ok "plugin.json 结构断言（name/version/license/author/hooks/skills 声明）"
else
  bad "plugin.json 结构断言失败"
fi

if "$PY" - "$HOOKS_JSON" <<'PYEOF'
import json, sys
h = json.load(open(sys.argv[1], encoding="utf-8"))
pre = h["hooks"]["PreToolUse"]
assert len(pre) == 1, "PreToolUse 应恰好 1 组"
g = pre[0]
assert g.get("matcher") == "Bash", "matcher 应为 Bash"
assert len(g["hooks"]) == 1 and g["hooks"][0]["type"] == "command", "应 command 型"
cmd = g["hooks"][0]["command"]
assert "guard_hook.py" in cmd, "command 应指向 guard_hook.py"
assert "${CLAUDE_PLUGIN_ROOT}" in cmd, "command 应使用 ${CLAUDE_PLUGIN_ROOT}"
print("ok")
PYEOF
then
  ok "hooks.json 结构断言（PreToolUse/Bash/command 型/CLAUDE_PLUGIN_ROOT）"
else
  bad "hooks.json 结构断言失败"
fi

# ------------------------------------------- 2) 服务地址对齐（默认 127.0.0.1:8155）
if "$PY" - "$GUARD" <<'PYEOF'
import sys
src = open(sys.argv[1], encoding="utf-8").read()
ns = {}
exec(compile(src, sys.argv[1], "exec"), ns)
assert ns["BUILTIN_DEFAULTS"]["server"] == "http://127.0.0.1:8155", \
    "guard 内置默认 server 应为 http://127.0.0.1:8155"
print("ok")
PYEOF
then
  ok "guard.py 内置默认 server = http://127.0.0.1:8155"
else
  bad "guard.py 内置默认 server 断言失败"
fi
if ! grep -q -- '--server' "$HOOK"; then
  ok "hook 不覆盖服务地址参数（沿用 guard 默认 8155，逐项对齐）"
else
  bad "hook 源码出现 --server（应沿用 guard 默认）"
fi

# ------------------------------------------------------- 3) guard.py 直连断言
"$PY" "$GUARD" --command "git status" >"$TMP/g1.json" 2>/dev/null; rc=$?
if [ "$rc" -eq 0 ]; then ok "guard 直连：良性 git status → exit 0 (allow)"
else bad "guard 直连：良性命令 exit=$rc 期望 0"; fi

"$PY" "$GUARD" --command "rm -rf /" >"$TMP/g2.json" 2>/dev/null; rc=$?
if [ "$rc" -eq 1 ]; then ok "guard 直连：危险 rm -rf / → exit 1 (deny)"
else bad "guard 直连：危险命令 exit=$rc 期望 1"; fi

"$PY" "$GUARD" --command "npm install -g typescript" >"$TMP/g3.json" 2>/dev/null; rc=$?
if [ "$rc" -eq 1 ]; then ok "guard 直连：灰区（L1 默认关闭）→ exit 1 (fail-closed=deny)"
else bad "guard 直连：灰区 exit=$rc 期望 1"; fi

# ------------------------------------------------- 4) hook 链路（L1 关闭基线）
run_hook() { # $1=command  $2=输出json文件
  "$PY" "$HOOK" >"$2" 2>"$TMP/hook.err" <<EOF
{"session_id":"self-test","transcript_path":"$TMP/transcript.jsonl","cwd":"$TMP","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"$1","description":"self-test"}}
EOF
}

hook_decision() { # $1=json文件 -> permissionDecision
  "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1],encoding="utf-8")); print(d["hookSpecificOutput"]["permissionDecision"])' "$1" 2>/dev/null
}
hook_event() { # $1=json文件 -> hookEventName
  "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1],encoding="utf-8")); print(d["hookSpecificOutput"]["hookEventName"])' "$1" 2>/dev/null
}

run_hook "git status" "$TMP/h1.json"; rc=$?
if [ "$rc" -eq 0 ] && [ "$(hook_decision "$TMP/h1.json")" = "allow" ] \
   && [ "$(hook_event "$TMP/h1.json")" = "PreToolUse" ]; then
  ok "hook 链路：良性 git status → exit 0 + PreToolUse/allow"
else
  bad "hook 链路：良性命令 rc=$rc 期望 exit 0 + allow（out=$(cat "$TMP/h1.json" 2>/dev/null)）"
fi

run_hook "rm -rf /" "$TMP/h2.json"; rc=$?
if [ "$rc" -eq 2 ] && [ "$(hook_decision "$TMP/h2.json")" = "deny" ]; then
  ok "hook 链路：危险 rm -rf / → exit 2 + deny"
else
  bad "hook 链路：危险命令 rc=$rc 期望 exit 2 + deny（out=$(cat "$TMP/h2.json" 2>/dev/null)）"
fi

run_hook "npm install -g typescript" "$TMP/h3.json"; rc=$?
if [ "$rc" -eq 2 ] && [ "$(hook_decision "$TMP/h3.json")" = "deny" ]; then
  ok "hook 链路：灰区（L1 关闭）→ exit 2 + deny（fail-closed）"
else
  bad "hook 链路：灰区 rc=$rc 期望 exit 2 + deny（out=$(cat "$TMP/h3.json" 2>/dev/null)）"
fi

# ------------------------------------------- 5) L1 端到端（mock @127.0.0.1:8155）
echo "== L1 端到端（本地 mock 起在 127.0.0.1:8155）=="
"$PY" "$ROOT/mock_server.py" --port 8155 --rules "$ROOT/mock_rules.json" \
    >"$TMP/mock.log" 2>&1 &
MOCK_PID=$!
mock_ready=0
for _ in $(seq 1 50); do
  if kill -0 "$MOCK_PID" 2>/dev/null \
     && "$PY" -c '
import json, urllib.request
try:
    with urllib.request.urlopen("http://127.0.0.1:8155/health", timeout=0.4) as r:
        d = json.loads(r.read().decode())
        raise SystemExit(0 if d.get("model") == "phocinae-mock-0" else 1)
except Exception:
    raise SystemExit(1)' 2>/dev/null; then
    mock_ready=1; break
  fi
  sleep 0.1
done

if [ "$mock_ready" -ne 1 ]; then
  skip "L1 端到端：8155 不可用或已被非 mock 服务占用（$(head -c 200 "$TMP/mock.log" 2>/dev/null)）"
  kill "$MOCK_PID" 2>/dev/null || true
  wait "$MOCK_PID" 2>/dev/null || true
  MOCK_PID=""
else
  export PHOCINAE_GUARD_L1_ENABLED=1
  run_hook "npm install -g typescript" "$TMP/h4.json"; rc=$?
  if [ "$rc" -eq 2 ] && [ "$(hook_decision "$TMP/h4.json")" = "ask" ]; then
    ok "L1 端到端：npm install -g → exit 2 + ask（mock noul=0.5/score=5.0，命中 8155 默认 server）"
  else
    bad "L1 端到端：npm -g rc=$rc 期望 ask（out=$(cat "$TMP/h4.json" 2>/dev/null)）"
  fi
  run_hook "pip install requests" "$TMP/h5.json"; rc=$?
  if [ "$rc" -eq 0 ] && [ "$(hook_decision "$TMP/h5.json")" = "allow" ]; then
    ok "L1 端到端：pip install → exit 0 + allow（mock noul=0.9/score=2.5）"
  else
    bad "L1 端到端：pip install rc=$rc 期望 allow（out=$(cat "$TMP/h5.json" 2>/dev/null)）"
  fi
  run_hook "rm -rf /" "$TMP/h6.json"; rc=$?
  if [ "$rc" -eq 2 ] && [ "$(hook_decision "$TMP/h6.json")" = "deny" ]; then
    ok "L1 端到端：危险命令仍被 L0 优先 deny（黑名单先于模型）"
  else
    bad "L1 端到端：L1 开启时 rm -rf / rc=$rc 期望 deny"
  fi
  unset PHOCINAE_GUARD_L1_ENABLED
  kill "$MOCK_PID" 2>/dev/null || true
  wait "$MOCK_PID" 2>/dev/null || true
  MOCK_PID=""
fi

# ---------------------------------------------------------------- 6) 审计落盘
if [ -s "$TMP/audit.jsonl" ]; then
  rows=$(wc -l < "$TMP/audit.jsonl" | tr -d ' ')
  if "$PY" - "$TMP/audit.jsonl" <<'PYEOF'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
assert len(rows) >= 4, "审计行数不足"
for r in rows:
    for k in ("ts", "command", "cwd", "decision", "layer", "reason"):
        assert k in r, "缺字段 %s" % k
    assert r["decision"] in ("allow", "deny", "ask"), "非法 decision"
assert any(r["decision"] == "allow" for r in rows), "缺 allow 记录"
assert any(r["decision"] == "deny" for r in rows), "缺 deny 记录"
PYEOF
  then
    ok "审计 JSONL 落盘：$rows 行、字段齐全、含 allow+deny"
  else
    bad "审计 JSONL 内容校验失败"
  fi
else
  bad "审计文件未生成"
fi

echo
echo "== 结果：PASS=$PASS FAIL=$FAIL SKIP=$SKIP =="
if [ "$FAIL" -ne 0 ]; then
  echo "SELF-TEST FAILED"
  exit 1
fi
echo "SELF-TEST OK"
exit 0
