from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any

from .demangle import demangle_symbol
from .entitlements import diff_entitlements
from .models import BinaryAnalysis, Function


def _score(old: Function, new: Function) -> tuple[int, dict[str, Any]]:
    size_delta = abs((new.size or 0) - (old.size or 0))
    baseline_size = max(old.size or 0, new.size or 0, 1)
    size_score = min(60, round(size_delta / baseline_size * 60))
    calls_available = bool(old.calls or new.calls)
    calls_added = len(set(new.calls) - set(old.calls)) if calls_available else 0
    calls_removed = len(set(old.calls) - set(new.calls)) if calls_available else 0
    evidence = {
        "size_delta_bytes": size_delta,
        "size_change_ratio": round(size_delta / baseline_size, 3),
        "call_data_available": calls_available,
        "calls_added": calls_added,
        "calls_removed": calls_removed,
    }
    return min(100, size_score + 20 * (calls_added + calls_removed)), evidence


def _unique_by_name(functions: list[Function]) -> tuple[dict[str, Function], list[str]]:
    grouped: dict[str, list[Function]] = {}
    for function in functions:
        if function.name:
            grouped.setdefault(function.name, []).append(function)
    return (
        {name: values[0] for name, values in grouped.items() if len(values) == 1},
        sorted(name for name, values in grouped.items() if len(values) > 1),
    )


def _diff_security_signals(old_signals: list[Any], new_signals: list[Any]) -> dict[str, Any]:
    old_map = {s["category"]: s for s in old_signals}
    new_map = {s["category"]: s for s in new_signals}

    added_categories = sorted(set(new_map) - set(old_map))
    removed_categories = sorted(set(old_map) - set(new_map))
    expanded = []

    for cat in sorted(set(old_map) & set(new_map)):
        old_ev = set(old_map[cat].get("evidence", []))
        new_ev = set(new_map[cat].get("evidence", []))
        newly_added_evidence = sorted(new_ev - old_ev)
        if newly_added_evidence:
            expanded.append({
                "category": cat,
                "newly_observed": newly_added_evidence,
                "rationale": new_map[cat].get("rationale", ""),
            })

    return {
        "added_categories": [new_map[c] for c in added_categories],
        "removed_categories": [old_map[c] for c in removed_categories],
        "expanded_categories": expanded,
        "has_changes": bool(added_categories or removed_categories or expanded),
    }


def _diff_fileset_entries(old_entries: list[dict], new_entries: list[dict]) -> dict[str, Any]:
    old_map = {e["name"]: e for e in old_entries}
    new_map = {e["name"]: e for e in new_entries}

    added = sorted(set(new_map) - set(old_map))
    removed = sorted(set(old_map) - set(new_map))
    modified = []
    unchanged = []

    for name in sorted(set(old_map) & set(new_map)):
        e1, e2 = old_map[name], new_map[name]
        s1 = e1.get("size_bytes", 0)
        s2 = e2.get("size_bytes", 0)
        h1 = e1.get("sha256", "")
        h2 = e2.get("sha256", "")
        if h1 != h2 or s1 != s2:
            modified.append({
                "name": name,
                "size_delta_bytes": s2 - s1,
                "old_size_bytes": s1,
                "new_size_bytes": s2,
            })
        else:
            unchanged.append(name)

    # Sort modified entries so non-zero size changes appear first
    modified.sort(key=lambda x: (abs(x["size_delta_bytes"]), x["name"]), reverse=True)

    return {
        "added": added,
        "removed": removed,
        "modified": modified,
        "unchanged": unchanged,
        "has_fileset": bool(old_entries or new_entries),
    }


def diff_binaries(
    old: BinaryAnalysis,
    new: BinaryAnalysis,
    *,
    filter_pattern: str | None = None,
    min_score: int | None = None,
) -> dict:
    old_by_name, old_ambiguous = _unique_by_name(old.functions)
    new_by_name, new_ambiguous = _unique_by_name(new.functions)

    added = sorted(set(new_by_name) - set(old_by_name))
    removed = sorted(set(old_by_name) - set(new_by_name))
    modified, unchanged = [], []

    filter_re = re.compile(filter_pattern, re.IGNORECASE) if filter_pattern else None

    for name in sorted(set(old_by_name) & set(new_by_name)):
        before, after = old_by_name[name], new_by_name[name]
        score, evidence = _score(before, after)
        demangled = before.demangled_name or after.demangled_name or demangle_symbol(name)

        if filter_re:
            # Match against raw symbol name or demangled name
            if not (filter_re.search(name) or filter_re.search(demangled)):
                continue

        if score:
            if min_score is not None and score < min_score:
                continue
            modified.append({
                "function": name,
                "demangled_name": demangled if demangled != name else None,
                "before": asdict(before),
                "after": asdict(after),
                "change_significance": score,
                "evidence": evidence,
            })
        else:
            unchanged.append(name)

    # Filter added / removed names if filter_pattern is set
    if filter_re:
        added = [n for n in added if filter_re.search(n) or filter_re.search(demangle_symbol(n))]
        removed = [n for n in removed if filter_re.search(n) or filter_re.search(demangle_symbol(n))]

    modified.sort(key=lambda item: item["change_significance"], reverse=True)

    old_dict = old.to_dict()
    new_dict = new.to_dict()

    signals_delta = _diff_security_signals(
        old_dict.get("security_signals", []),
        new_dict.get("security_signals", []),
    )

    entitlements_delta = diff_entitlements(
        old_dict.get("entitlements", {}),
        new_dict.get("entitlements", {}),
    )

    fileset_delta = _diff_fileset_entries(
        old_dict.get("fileset_entries", []),
        new_dict.get("fileset_entries", []),
    )

    return {
        "observed_facts": {"old": old_dict, "new": new_dict},
        "function_changes": {
            "added": added,
            "removed": removed,
            "modified": modified,
            "unchanged": unchanged,
            "ambiguous_names_not_matched": sorted(set(old_ambiguous + new_ambiguous)),
        },
        "fileset_changes": fileset_delta,
        "security_signals_delta": signals_delta,
        "entitlements_delta": entitlements_delta,
        "filter_applied": {
            "pattern": filter_pattern,
            "min_score": min_score,
        },
        "methodology": {
            "matching": "exact unique function-name match with C++/Swift demangling; fileset KEXT load command parsing for modern Mach-O kernel collections",
            "change_significance": "size component: min(60, round(size delta / max(function size) * 60)); plus 20 points per changed call only when call data is available; not a vulnerability score",
        },
    }


def llm_evidence(report: dict, max_modified_functions: int = 25) -> dict:
    changes = report["function_changes"]
    sig_delta = report.get("security_signals_delta", {})
    ent_delta = report.get("entitlements_delta", {})
    kext_delta = report.get("fileset_changes", {})

    modified_clean = []
    for item in changes["modified"][:max_modified_functions]:
        modified_clean.append({
            "function": item["demangled_name"] or item["function"],
            "raw_symbol": item["function"] if item["demangled_name"] else None,
            "change_significance": item["change_significance"],
            "evidence": item["evidence"],
        })

    evidence = {
        "evidence_version": 2,
        "methodology": report["methodology"],
        "function_changes": {
            "added": [demangle_symbol(n) for n in changes["added"][:100]],
            "removed": [demangle_symbol(n) for n in changes["removed"][:100]],
            "modified": modified_clean,
            "ambiguous_names_not_matched": changes["ambiguous_names_not_matched"][:50],
        },
        "security_surface_changes": {
            "added_security_categories": [s["category"] for s in sig_delta.get("added_categories", [])],
            "removed_security_categories": [s["category"] for s in sig_delta.get("removed_categories", [])],
            "expanded_security_categories": [s["category"] for s in sig_delta.get("expanded_categories", [])],
        },
        "entitlements_changes": {
            "added_entitlements": list(ent_delta.get("added", {}).keys()),
            "removed_entitlements": list(ent_delta.get("removed", {}).keys()),
            "security_alerts": ent_delta.get("security_alerts", []),
        },
        "limitations": [
            "Signals are deterministic triage observations, not vulnerability findings.",
            "Function matching uses symbol names and demangled aliases.",
        ],
    }

    if kext_delta.get("has_fileset"):
        evidence["kernel_subsystem_modules"] = {
            "total_modules": len(kext_delta.get("modified", [])) + len(kext_delta.get("unchanged", [])),
            "modified_modules": [
                {
                    "name": m["name"],
                    "size_delta_bytes": m["size_delta_bytes"],
                    "old_size_bytes": m["old_size_bytes"],
                    "new_size_bytes": m["new_size_bytes"],
                }
                for m in kext_delta.get("modified", [])[:15]
            ],
            "added_modules": kext_delta.get("added", []),
            "removed_modules": kext_delta.get("removed", []),
        }

    return evidence
