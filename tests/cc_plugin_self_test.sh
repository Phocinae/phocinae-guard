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
# 用法：bash tests/cc_plugin_self_test.sh（退出码 0 = 全绿）
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 解释器探测：Windows 上没有 python3（Git bash 里也没有）。
# 优先 ${PHOCINAE_CC_PY}，否则依次试 $PY / python / py -3。
if [ -n "${PHOCINAE_CC_PY:-}" ]; then
    PY="$PHOCINAE_CC_PY"
else
    PY=""
    for cand in python3 python; do
        if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
    done
    if [ -z "$PY" ] && command -v py >/dev/null 2>&1; then PY="py -3"; fi
fi
if [ -z "$PY" ]; then
    echo "无法找到 Python 解释器；设 PHOCINAE_CC_PY=/path/to/python 后重试" >&2
    exit 2
fi
echo "interpreter: $PY"

# 交给 Python 子进程用的 bash —— 必须是**正在跑本自测的这个 bash**（Git Bash）。
#
# 不能让它自己去 PATH 里找 `bash`：在 Windows 上 PATH 里的 `bash` 往往是 WSL 的
# C:\WINDOWS\system32\bash.exe，它看不到 `D:/...` 这种路径，会报
# "No such file or directory" —— 实测踩过，报错里还夹着 WSL 自己的 localhost 提示。
#
# 注意这只影响**自测**：产品命令里的 `bash` 由 Claude Code 交给 Git Bash 执行，
# 而 Git Bash 的 PATH 把 /usr/bin 放在最前，所以那里解析到的是 Git Bash 自己
# （实测：Git Bash 内 `command -v bash` → /usr/bin/bash）。
SELF_BASH="$(command -v bash)"
if command -v cygpath >/dev/null 2>&1; then
    SELF_BASH="$(cygpath -w "$SELF_BASH")"
fi
export PHOCINAE_SELF_BASH="$SELF_BASH"
echo "self-test bash: $SELF_BASH"

PLUGIN_JSON="$ROOT/.claude-plugin/plugin.json"
HOOKS_JSON="$ROOT/hooks/hooks.json"
HOOK="$ROOT/hooks/guard_hook.py"
GUARD="$ROOT/guard.py"

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

echo "== phocinae-guard Claude Code 插件自测（root=${ROOT}）=="

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

if "$PY" - "$PLUGIN_JSON" "$ROOT/guard.py" <<'PYEOF'
import json, re, sys
p = json.load(open(sys.argv[1], encoding="utf-8"))
guard_src = open(sys.argv[2], encoding="utf-8").read()
guard_version = re.search(r'^VERSION\s*=\s*"([^"]+)"', guard_src, re.M).group(1)
assert p["name"] == "phocinae-guard", "name 不符"
# 版本号必须与 guard.py 的 VERSION 一致：写死字面量会在每次发布后失效，
# 而那属于测试漂移，不是插件缺陷。这里断言两者不漂移。
assert p["version"] == guard_version, (
    "version 不符：plugin.json=%r guard.py=%r" % (p["version"], guard_version))
assert re.match(r"^\d+\.\d+\.\d+", p["version"]), "version 不是 x.y.z"
assert p["license"] == "Apache-2.0", "license 不符"
assert isinstance(p.get("author"), dict) and p["author"].get("name"), "author 缺失"
# author 必须是本项目，不能是别的组织（曾误写成 "Nous Research"）
assert "phocinae" in p["author"]["name"].lower(), "author 不是 Phocinae"
assert p.get("hooks", "").endswith("hooks.json"), "hooks 组件声明缺失"
# hooks.json 必须位于插件根的 hooks/ 下（官方插件形态），
# 不在 .claude-plugin/ 里 —— 后者市场装载找不到
assert p["hooks"] == "./hooks/hooks.json", (
    "hooks 路径不符合官方形态：%r" % p["hooks"])
assert p.get("skills", "").startswith("./"), "skills 组件声明缺失"
assert p["skills"] == "./skills", "skills 路径不符合官方形态：%r" % p["skills"]
print("ok")
PYEOF
then
  ok "plugin.json 结构断言（name/version/license/author/hooks/skills 声明）"
else
  bad "plugin.json 结构断言失败"
fi

if "$PY" - "$HOOKS_JSON" "$ROOT" <<'PYEOF'
import json, os, re, shlex, shutil, subprocess, sys
h = json.load(open(sys.argv[1], encoding="utf-8"))
root = sys.argv[2]
pre = h["hooks"]["PreToolUse"]
assert len(pre) == 1, "PreToolUse 应恰好 1 组"
g = pre[0]
matcher = g.get("matcher") or ""
# matcher 必须覆盖 shell 与文件写入两族。
# 只写 "Bash" 时，Write/Edit/MCP 工具根本不经过本 hook —— 门形同不存在，
# 而它「没报错」这一点会让所有别的检查继续全绿。
for token in ("Bash", "Write", "Edit", "mcp__"):
    assert token in matcher, "matcher 未覆盖 %s：%r" % (token, matcher)
assert len(g["hooks"]) == 1 and g["hooks"][0]["type"] == "command", "应 command 型"
handler = g["hooks"][0]
cmd = handler["command"]
assert "guard_hook.py" in cmd, "command 应指向 guard_hook.py"
assert "${CLAUDE_PLUGIN_ROOT}" in cmd, "command 应使用 ${CLAUDE_PLUGIN_ROOT}"

resolved = cmd.replace("${CLAUDE_PLUGIN_ROOT}", root).replace("$CLAUDE_PLUGIN_ROOT", root)

# ---------------------------------------------------------------------------
# 0.1.9：命令里那个**失败守卫**必须是 fail-closed 的。
#
# 官方文档：hook 失败/超时时，Claude Code 默认**照常执行**该动作
# （"a policy hook with a wrong path or a crashing script lets everything
#   through"）。所以"门跑不起来"必须显式转成阻断，否则等于门不存在。
# ---------------------------------------------------------------------------
m = re.search(r"\|\|\s*exit\s+2\s*$", resolved)
assert m, ("command 必须以 `|| exit 2` 收尾，否则门跑不起来时会静默放行：%r" % cmd)
body = resolved[:m.start()].rstrip()

parts = shlex.split(body)
assert len(parts) >= 2, "command 至少要有启动器 + 脚本路径：%r" % cmd

# ★ 断言 1：脚本路径必须真实存在。
#
# 这一条是 0.1.8 加的，代价实测过：command 曾写成
#   ${CLAUDE_PLUGIN_ROOT}/.claude-plugin/hooks/guard_hook.py
# 而 .claude-plugin/ 下只有 plugin.json，真实文件在 hooks/guard_hook.py。
script = parts[-1]
assert os.path.isfile(script), (
    "hook command 指向的文件不存在：%r（command=%r，展开后=%r）" % (script, cmd, resolved))

# ★★ 断言 2（0.1.9 新增）：命令的第一个 token（解释器**或启动器**）必须真的能跑。
#
# 0.1.8 及以前这里是 `python3 "..."`，而 **Windows 上没有 python3**（Git Bash 也没有
# ——它的 PATH 就是 Windows PATH 的 POSIX 形式，装 Git Bash 造不出 python3）。
# 于是 hook 以 127 启动失败；Claude Code 把 hook 启动失败当**非阻断错误**，
# 门不运行，每一次 Bash / Write / Edit 都落回正常权限流。
#
# 这条断言以前**不存在**，所以自测在本机 Windows 上照样全绿：脚本文件确实在，
# 而自测自己的解释器探测（见本文件开头）会去找到 `python`，于是它测的是
# "我自己能不能跑 hook"，不是"**发布出去的那条命令**能不能跑 hook"。
launcher = parts[0]
assert shutil.which(launcher) or os.path.isfile(launcher), (
    "hook command 的启动器 %r 在本机找不到（command=%r）—— "
    "这正是「插件装上了、门从不运行」的形态" % (launcher, cmd))

# 跑的时候用**本自测自己所在的 bash**，不要用 PATH 解析出来的那个：
# Windows 上 PATH 里的 `bash` 可能是 WSL 的，它看不到 D:/... 路径。
# （产品路径不受影响，见本文件开头的 SELF_BASH 注释。）
SHELL_BIN = os.environ.get("PHOCINAE_SELF_BASH") or launcher

# 光"找得到"还不够，还要真跑一次：Windows 上 python3 常指向 Microsoft Store
# 的应用执行别名，它在非 TTY 子进程里**静默 exit 49**，shutil.which() 认为可用。
probe = subprocess.run([SHELL_BIN, "-c", ""], capture_output=True,
                       encoding="utf-8", errors="replace")
assert probe.returncode == 0, (
    "hook command 的启动器 %r 存在但跑不起来（exit=%s, stderr=%r）"
    % (launcher, probe.returncode, (probe.stderr or "")[:200]))

# ★★★ 断言 3（0.1.9 新增，最强的一条）：把**发布出去的那条命令原样跑一次**，
# 喂真实 PreToolUse 事件，要求它真的产出裁决 —— 良性放行、危险拦截。
# 前两条只证明"文件在、启动器找得到"；这一条证明"门真的在判"。
CASES = [
    ("git status", 0, "allow"),
    ("rm -rf /", 2, "deny"),
]
for command, want_exit, want_decision in CASES:
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    r = subprocess.run([SHELL_BIN, "-c", resolved], input=payload, capture_output=True,
                       encoding="utf-8", errors="replace")
    assert r.returncode == want_exit, (
        "命令 %r 期望 exit %d，实际 %d（stderr=%r）"
        % (command, want_exit, r.returncode, (r.stderr or "")[:300]))
    try:
        decision = (json.loads(r.stdout or "{}").get("hookSpecificOutput") or {})
        decision = decision.get("permissionDecision")
    except ValueError:
        decision = None
    assert decision == want_decision, (
        "命令 %r 期望 permissionDecision=%r，实际 %r（stdout=%r）"
        % (command, want_decision, decision, (r.stdout or "")[:300]))

print("resolved hook script : %s" % script)
print("launcher             : %s" % launcher)
print("end-to-end           : benign=allow/0  dangerous=deny/2")
print("ok")
PYEOF
then
  ok "hooks.json 的启动器可跑 + 端到端产出真实裁决（良性 allow / 危险 deny），且带 fail-closed 守卫"
else
  bad "hooks.json 的启动器不可用，或端到端没有产出裁决（门装上了却不运行）"
fi

# 反向验证 A：把命令改回那个不存在的路径，断言 1 必须失败。
# 没有这一步，就无法证明那条断言真的在检查它声称检查的东西。
if "$PY" - "$ROOT" <<'PYEOF'
import os, shlex, sys
root = sys.argv[1]
broken = 'python3 "${CLAUDE_PLUGIN_ROOT}/.claude-plugin/hooks/guard_hook.py"'
resolved = broken.replace("${CLAUDE_PLUGIN_ROOT}", root)
script = shlex.split(resolved)[-1]
# 期望：文件不存在（即旧路径确实是坏的）
if os.path.isfile(script):
    print("unexpected: %r exists" % script)
    sys.exit(1)
sys.exit(0)
PYEOF
then
  ok "反向验证 A：旧的 .claude-plugin/hooks/ 路径确实不存在（断言 1 非空转）"
else
  bad "反向验证 A 失败：旧路径居然存在，说明断言 1 指向了别的东西"
fi

# 反向验证 B（0.1.9 新增）：用一个**在任何平台上都不存在**的启动器，
# 断言 2 必须失败 —— 证明它查的是"启动器可不可用"，而不是恒真。
# 用 python3.99 而不是 python3：后者在 Linux CI 上存在，会让这条反向验证
# 在别的机器上变成假绿。
if "$PY" - <<'PYEOF'
import shlex, shutil, sys
launcher = shlex.split('python3.99 "/x/hooks/guard_hook.py"')[0]
if shutil.which(launcher) or shutil.which(launcher):
    print("unexpected: %r resolved" % launcher)
    sys.exit(1)
sys.exit(0)
PYEOF
then
  ok "反向验证 B：不存在的启动器确实解析不了（断言 2 非空转）"
else
  bad "反向验证 B 失败：一个不该存在的解释器居然被解析到了"
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
