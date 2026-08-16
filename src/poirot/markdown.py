# Markdown report generator for Poirot diff and IPSW comparison reports.
# Produces clean, GitHub-flavored Markdown audit writeups.
from __future__ import annotations

from typing import Any
from pathlib import Path


def generate_markdown_report(report: dict[str, Any]) -> str:
    # Formats a complete structured Markdown report from a diff dictionary
    lines: list[str] = []

    if report.get("kind") == "ipsw_diff":
        old_a = report["old_archive"]
        new_a = report["new_archive"]
        build = report["build_changes"]
        comp = report["component_changes"]

        lines.append("# Poirot — IPSW Firmware Differential Report\n")
        lines.append("| Field | Old Firmware | New Firmware |")
        lines.append("| :--- | :--- | :--- |")
        lines.append(f"| **Archive** | `{Path(old_a['path']).name}` | `{Path(new_a['path']).name}` |")
        lines.append(f"| **Product Version** | `{old_a.get('product_version') or '?'}` | `{new_a.get('product_version') or '?'}` |")
        lines.append(f"| **Build Number** | `{old_a.get('build_number') or '?'}` | `{new_a.get('build_number') or '?'}` |")
        lines.append(f"| **Total Payloads** | {old_a.get('total_members', 0):,} | {new_a.get('total_members', 0):,} |")
        lines.append("")

        lines.append("## Component Summary\n")
        lines.append(f"- **Added Components**: {comp['total_added']}")
        lines.append(f"- **Removed Components**: {comp['total_removed']}")
        lines.append(f"- **Modified Components**: {comp['total_modified']}")
        lines.append(f"- **Unchanged Components**: {comp['total_unchanged']}")
        lines.append("")

        hotspots = report.get("security_hotspots", [])
        if hotspots:
            lines.append("## Modified Security Subsystems\n")
            for h in hotspots:
                lines.append(f"- `[! risks/hotspot]` **{h}**")
            lines.append("")

        modified = comp.get("modified_components", [])
        if modified:
            lines.append("## Modified Firmware Payloads\n")
            lines.append("| Component | Subsystem | Size Delta | Old CRC | New CRC |")
            lines.append("| :--- | :---: | :---: | :---: | :---: |")
            for item in modified[:50]:
                delta = item["size_delta_bytes"]
                delta_str = f"+{delta:,} B" if delta > 0 else f"{delta:,} B" if delta < 0 else "0 B"
                lines.append(f"| `{item['filename']}` | `{item['category']}` | {delta_str} | `{item['old_crc']}` | `{item['new_crc']}` |")
            lines.append("")

        return "\n".join(lines)

    # Standard Binary Diff Report
    obs = report["observed_facts"]
    changes = report["function_changes"]
    sig_delta = report.get("security_signals_delta", {})
    ent_delta = report.get("entitlements_delta", {})

    lines.append("# Poirot — Binary Differential Report\n")
    lines.append("| Property | Base Binary | Target Binary |")
    lines.append("| :--- | :--- | :--- |")
    lines.append(f"| **Path** | `{obs['old']['path']}` | `{obs['new']['path']}` |")
    lines.append(f"| **Format** | {obs['old']['format']} | {obs['new']['format']} |")
    lines.append(f"| **Architecture** | {obs['old'].get('architecture', '?')} | {obs['new'].get('architecture', '?')} |")
    lines.append("")

    lines.append("## Summary Statistics\n")
    lines.append(f"- **Added Functions**: {len(changes['added'])}")
    lines.append(f"- **Removed Functions**: {len(changes['removed'])}")
    lines.append(f"- **Modified Functions**: {len(changes['modified'])}")
    lines.append(f"- **Unchanged Functions**: {len(changes['unchanged'])}")
    lines.append("")

    # Security Signal Delta
    if sig_delta.get("has_changes"):
        lines.append("## Attack Surface & Security Signal Changes\n")
        for item in sig_delta.get("added_categories", []):
            lines.append(f"- **+ Added `{item['category']}`**: {item['rationale']}")
        for item in sig_delta.get("expanded_categories", []):
            ev_str = ", ".join(item["newly_observed"][:5])
            lines.append(f"- **~ Expanded `{item['category']}`**: newly observed {ev_str}")
        for item in sig_delta.get("removed_categories", []):
            lines.append(f"- **- Removed `{item['category']}`**")
        lines.append("")

    # Entitlements Delta
    if ent_delta.get("has_changes"):
        lines.append("## Entitlements Differential\n")
        for alert in ent_delta.get("security_alerts", []):
            lines.append(f"> [!] **Security Alert**: {alert}\n")
        if ent_delta.get("added"):
            lines.append("### Added Entitlements")
            for k, v in ent_delta["added"].items():
                lines.append(f"- `+ {k}`: `{v}`")
            lines.append("")
        if ent_delta.get("removed"):
            lines.append("### Removed Entitlements")
            for k, v in ent_delta["removed"].items():
                lines.append(f"- `- {k}`: `{v}`")
            lines.append("")
        if ent_delta.get("modified"):
            lines.append("### Modified Entitlements")
            for k, v in ent_delta["modified"].items():
                lines.append(f"- `~ {k}`: `{v['before']}` -> `{v['after']}`")
            lines.append("")

    # Modified Functions Table
    modified = changes.get("modified", [])
    if modified:
        lines.append("## Modified Functions (Ranked by Significance)\n")
        lines.append("| Function / Symbol | Significance Score | Size Delta | Calls Added | Calls Removed |")
        lines.append("| :--- | :---: | :---: | :---: | :---: |")
        for item in modified[:50]:
            name = item.get("demangled_name") or item["function"]
            score = item["change_significance"]
            ev = item["evidence"]
            lines.append(f"| `{name}` | **{score}** | {ev.get('size_delta_bytes', 0):,} B ({ev.get('size_change_ratio', 0):.1%}) | +{ev.get('calls_added', 0)} | -{ev.get('calls_removed', 0)} |")
        lines.append("")

    # Added / Removed Lists
    if changes.get("added"):
        lines.append("## Added Functions\n")
        for fn in changes["added"][:30]:
            lines.append(f"- `{fn}`")
        if len(changes["added"]) > 30:
            lines.append(f"- *...and {len(changes['added']) - 30} more*")
        lines.append("")

    if changes.get("removed"):
        lines.append("## Removed Functions\n")
        for fn in changes["removed"][:30]:
            lines.append(f"- `{fn}`")
        if len(changes["removed"]) > 30:
            lines.append(f"- *...and {len(changes['removed']) - 30} more*")
        lines.append("")

    # LLM Interpretation if bundled
    if report.get("llm_interpretation"):
        interp = report["llm_interpretation"]
        lines.append("## LLM Interpretation\n")
        lines.append(f"**Provider**: `{interp.get('provider')}` | **Model**: `{interp.get('model')}`\n")
        lines.append(interp.get("explanation", ""))
        lines.append("")

    return "\n".join(lines)
