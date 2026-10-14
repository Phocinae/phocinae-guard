#!/usr/bin/env bash
# phocinae-guard · Python 解释器探测 shim（Claude Code hook 的启动层）
#
# ---------------------------------------------------------------------------
# 为什么需要这一层，而不是让 hooks.json 直接写 `python3`：
#
#   Claude Code 的 shell form 命令，在 macOS/Linux 上交给 `sh -c`，
#   在 **Windows 上交给 Git Bash**（官方文档原文：shell form "is passed to a
#   shell: sh -c on macOS and Linux, Git Bash on Windows, or PowerShell when
#   Git Bash isn't installed"）。
#
#   Windows 上通常**没有** `python3`——Git Bash 也没有，因为 Git Bash 的 PATH
#   就是 Windows PATH 的 POSIX 形式，装 Git Bash 并不会造出一个 `python3`。
#   于是 `python3 "<hook>"` 以 127 退出：hook 启动失败属于**非阻断错误**，
#   门不运行，调用落回正常权限流 —— 每一次 Bash / Write / Edit 都放行。
#
#   这与 0.1.8 修掉的是**同一个形状**，只升了一层：那次是"路径不存在"，
#   这次是"解释器不存在"。两次都躲过了同一批检查，因为自测**自己探测**
#   解释器（找到 `python` 就跑起来了），而**从不校验 hooks.json 里写的那个**。
#
# 为什么探测要"真跑一次"，而不是 `command -v`：
#
#   Windows 上 `python3` 常常**存在**，但指向 Microsoft Store 的应用执行别名
#   (`...\WindowsApps\python3.exe`)。那个别名在非 TTY 子进程里**静默 exit 49**：
#   `command -v` 会认为它可用，而它什么都没做。又是一次"看起来在工作、
#   实际什么都没做"。所以每个候选都真的跑一次版本检查再采用。
#
#   这个探法与 Anthropic 自己 `security-guidance` 插件的 `sg-python.sh` 同源
#   （他们的注释点名了 WindowsApps stub、PYTHONUTF8、以及相应 issue）。
#
# 用法：run_guard.sh <要执行的脚本> [参数...]
# 退出：采用 exec，故退出码即被测脚本的退出码（0 = allow / 2 = 拦）。
#       找不到可用解释器时退出 1 —— hooks.json 里的 `|| exit 2` 会把它
#       转成**阻断**，这样"门跑不起来"不再等于"门不存在"。
# ---------------------------------------------------------------------------
set -u

if [ "$#" -eq 0 ]; then
    echo "phocinae-guard: run_guard.sh needs a script path to run." >&2
    exit 1
fi

# 必须在 Python 启动**之前**设好。
# 否则 Windows 上 Python 的 locale.getpreferredencoding() 是 cp936/cp1252，
# 而本项目的裁决理由是中文（"L0 黑名单 rm_system：…"），任何用 text 模式读
# 子进程输出的调用方都会在解码时崩掉，把"能跑"变成"看不到结果"。
export PYTHONUTF8=1

# 真跑一次：既确认它能启动，也确认它达到了 README 声称的下限。
# 下限取 3.8 而不是更高的版本，是**实测**的结果：对 guard.py / guard_hook.py /
# 包内两个文件逐个跑 ast.parse(feature_version=(3,N))，四个文件的语法下限都是 3.8
# （README 也是这么写的）。取高了会把当前在 3.8/3.9 上本来能用的用户弄坏 ——
# 那不是修 bug，是制造 bug。
# `py -3` 需要作为两个词传入，所以 probe 用 "$@" 而不是单个命令名。
probe() {
    "$@" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null
}

# 第 1 轮：带小版本号的二进制，降序（用户显式装的 python.org / Homebrew / pyenv）。
for cand in python3.13 python3.12 python3.11 python3.10; do
    if command -v "$cand" >/dev/null 2>&1 && probe "$cand"; then
        exec "$cand" "$@"
    fi
done

# 第 2 轮：裸解释器（Store 别名会在 probe 里被淘汰）。
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1 && probe "$cand"; then
        exec "$cand" "$@"
    fi
done

# 第 3 轮：Windows 的 py 启动器。
if command -v py >/dev/null 2>&1 && probe py -3; then
    exec py -3 "$@"
fi

# 找不到就**说清楚**再失败。这几行是给用户的唯一线索 ——
# 没有它，用户只会看到"授权被拒"而不知道为什么。
{
    echo "phocinae-guard: no working Python 3.8+ interpreter found."
    echo "  tried : python3.13, python3.12, python3.11, python3.10, python3, python, py -3"
    echo "  result: the approval gate cannot run, so this call is BLOCKED (fail-closed)."
    echo "  fix   : install Python 3.8+ and make sure it is on PATH."
    echo "          on Windows use https://python.org, not the Microsoft Store alias"
    echo "          (the Store alias exits 49 silently in a non-TTY subprocess)."
    echo "  escape: remove the phocinae-guard plugin to restore the normal permission flow."
} >&2
exit 1
