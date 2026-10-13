# -*- coding: utf-8 -*-
"""Remediation table checks.

The remediation hint exists so a deny is not a dead end. But a table of
"suggested alternatives" attached to a security gate has an obvious failure
mode: if any suggested command is itself dangerous, the table becomes a
documented way around the gate.

So the central assertion here is:

    **no `instead` command trips the blacklist.**

The check is written so it cannot pass vacuously: it asserts a coverage count and
fails if the count is zero or if any entry lacks a hint.

    python tests/test_remediation.py
"""

from __future__ import annotations

import importlib.util
import io
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_passed = 0
_failed = []


def check(label, condition, detail=""):
    global _passed
    if condition:
        _passed += 1
        return True
    _failed.append((label, detail))
    return False


def load_guard():
    path = os.path.join(REPO, "guard.py")
    spec = importlib.util.spec_from_file_location("guard_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    stream = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    guard = load_guard()
    table = guard.load_l0_table(None)

    blacklist = table["blacklist"]
    remediation = table.get("remediation") or {}

    check("R1 the blacklist is non-empty", len(blacklist) > 0, "%d entries" % len(blacklist))
    check(
        "R2 the blacklist has the expected 26 entries",
        len(blacklist) == 26,
        "found %d" % len(blacklist),
    )

    names = [entry[0] for entry in blacklist]

    # -- coverage, in both directions ------------------------------------
    covered = [name for name in names if isinstance(remediation.get(name), dict)]
    check(
        "R3 every blacklist rule has a remediation hint",
        len(covered) == len(names),
        "missing: %r" % sorted(set(names) - set(covered)),
    )
    check(
        "R4 every remediation hint has at least one `instead` command",
        all(
            isinstance(remediation[n].get("instead"), list) and remediation[n]["instead"]
            for n in covered
        ),
        "bad: %r" % [n for n in covered if not (isinstance(remediation[n].get("instead"), list) and remediation[n]["instead"])],
    )
    check(
        "R5 no remediation hint is orphaned (every key matches a rule)",
        set(remediation) <= set(names),
        "orphans: %r" % sorted(set(remediation) - set(names)),
    )
    check(
        "R6 every hint explains why the command is risky",
        all(isinstance(remediation[n].get("why"), str) and remediation[n]["why"] for n in covered),
        "missing 'why': %r" % [n for n in covered if not remediation[n].get("why")],
    )

    # -- the load-bearing assertion --------------------------------------
    # A suggested alternative must not be blocked by the gate that suggested it.
    offenders = []
    total_alternatives = 0
    for name in covered:
        for command in remediation[name]["instead"]:
            total_alternatives += 1
            decision, _reason, _layer, hit = guard.l0_judge(command, table)
            if decision == "deny":
                offenders.append((name, command, hit))
    check(
        "R7 no `instead` command trips the blacklist",
        not offenders,
        "these alternatives are themselves blocked: %r" % (offenders,),
    )
    check(
        "R8 the scan actually examined every alternative (not a vacuous pass)",
        total_alternatives >= len(names),
        "examined only %d alternatives for %d rules" % (total_alternatives, len(names)),
    )

    # -- the hint reaches the decision -----------------------------------
    result = guard.decide("rm -rf /etc", os.getcwd(), _config(guard))
    check("R9 a deny carries a remediation block", isinstance(result.get("remediation"), dict), repr(result.get("remediation")))
    if isinstance(result.get("remediation"), dict):
        check(
            "R10 the block names the rule that fired",
            result["remediation"].get("rule") == "rm_system",
            repr(result["remediation"].get("rule")),
        )
        check(
            "R11 the block carries copyable alternatives",
            isinstance(result["remediation"].get("instead"), list)
            and len(result["remediation"]["instead"]) >= 2,
            repr(result["remediation"].get("instead")),
        )

    # An allow must not carry remediation -- it would be noise, and worse, it
    # would suggest the gate had nearly blocked something it did not.
    allowed = guard.decide("git status", os.getcwd(), _config(guard))
    check("R12 an allow carries no remediation block", "remediation" not in allowed, repr(allowed.get("remediation")))

    # -- the exit-code contract must be untouched ------------------------
    check("R13 a deny still exits 1", guard.EXIT_DENY == 1, str(guard.EXIT_DENY))
    check("R14 an allow still exits 0", guard.EXIT_ALLOW == 0, str(guard.EXIT_ALLOW))
    check("R15 ask still exits 2", guard.EXIT_ASK == 2, str(guard.EXIT_ASK))
    check("R16 a usage error still exits 3", guard.EXIT_ERROR == 3, str(guard.EXIT_ERROR))
    check(
        "R17 --confirm still cannot lift a deny",
        guard.decide("rm -rf /", os.getcwd(), _config(guard))["decision"] == "deny",
    )

    # -- custom tables may extend the hints ------------------------------
    # The key is additive, so a table written for the previous release (no
    # `remediation` key at all) must still load, and its own hints must merge.
    custom = _custom_table(guard, {"my_rule": {"why": "w", "instead": ["echo hi"]}})
    check(
        "R18 a custom table's own hint merges in",
        custom["remediation"].get("my_rule", {}).get("instead") == ["echo hi"],
        repr(custom["remediation"].get("my_rule")),
    )
    check(
        "R19 built-in hints survive a custom table",
        "rm_system" in custom["remediation"],
        repr(sorted(custom["remediation"])[:5]),
    )
    check(
        "R20 the blacklist entry shape is still [name, regex, note]",
        all(isinstance(entry, list) and len(entry) == 3 for entry in custom["blacklist"]),
        "%r" % [e for e in custom["blacklist"] if not (isinstance(e, list) and len(e) == 3)][:2],
    )
    check(
        "R21 nothing was added to the whitelist to make a hint pass",
        "python -m pytest" in table["whitelist_prefix"],
        "the pytest prefix entry must be present (it was lost once)",
    )

    for label, detail in _failed:
        stream.write("  FAIL %s\n" % label)
        if detail:
            stream.write("       %s\n" % detail)
    stream.write(
        "test_remediation             PASS=%d FAIL=%d SKIP=0\n" % (_passed, len(_failed))
    )
    if _passed == 0:
        stream.write("FAIL: nothing was verified\n")
        return 1
    return 1 if _failed else 0


def _config(guard):
    """A minimal config with L1 off, matching the shipped default stance."""
    cfg = dict(guard.BUILTIN_DEFAULTS)
    cfg["l1_enabled"] = False
    cfg["l0_table_data"] = guard.load_l0_table(None)
    return cfg


def _custom_table(guard, remediation):
    """Load a table from a JSON file that supplies extra remediation hints."""
    import json

    scratch = os.environ.get("PHOCINAE_GUARD_TMP")
    if not scratch:
        scratch = os.path.join(os.path.dirname(REPO), ".phocinae-guard-tmp")
    if not os.path.isdir(scratch):
        os.makedirs(scratch, exist_ok=True)
    path = os.path.join(scratch, "custom-table-remediation.json")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump({"remediation": remediation}, handle, ensure_ascii=False)
    return guard.load_l0_table(path)


if __name__ == "__main__":
    sys.exit(main())
