"""Rich terminal formatting for Poirot CLI output.

Spinners and progress go to stderr so piped stdout stays clean.
Formatted results go to stdout.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Generator

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box

# Spinners / progress → stderr (doesn't interfere with piped JSON)
err = Console(stderr=True, highlight=False)
# Formatted output → stdout
out = Console(highlight=False)

# ⣾⣽⣻⢿⡿⣟⣯⣷ — rotating braille that looks like mechanical cogwheel teeth
SPINNER = "dots2"


def spinner(message: str, style: str = "cyan"):
    """Return a Rich Status context manager with cogwheel-style spinner."""
    return err.status(f"[{style}]{message}[/]", spinner=SPINNER, spinner_style=style)


# ─── Analysis ─────────────────────────────────────────────────────────


def display_analysis(result: dict) -> None:
    """Format binary analysis for human reading."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", min_width=14)
    grid.add_column()

    grid.add_row("File", result["path"])
    grid.add_row("Format", result["format"])
    if result.get("architecture"):
        grid.add_row("Architecture", result["architecture"])
    if result.get("entry_point") is not None:
        grid.add_row("Entry Point", f"0x{result['entry_point']:X}")
    if result.get("executable_sections"):
        grid.add_row("Sections", ", ".join(result["executable_sections"]))

    counts = []
    if result.get("imports"):
        counts.append(f"{len(result['imports'])} imports")
    if result.get("exports"):
        counts.append(f"{len(result['exports'])} exports")
    if result.get("functions"):
        counts.append(f"{len(result['functions'])} functions")
    if counts:
        grid.add_row("Symbols", " · ".join(counts))
    if result.get("strings"):
        grid.add_row("Strings", f"{len(result['strings'])} extracted")

    out.print(Panel(grid, title="[bold]Binary Analysis[/]", border_style="cyan", box=box.ROUNDED))

    # Security signals
    signals = result.get("security_signals", [])
    if signals:
        out.print()
        out.print("[bold yellow]  Security Signals[/]")
        for signal in signals:
            evidence_str = ", ".join(signal["evidence"][:3])
            if len(signal["evidence"]) > 3:
                evidence_str += f" (+{len(signal['evidence']) - 3} more)"
            out.print(f"    [yellow][!][/] [bold]{signal['category']:<18}[/] {evidence_str}")

    # Parser notes
    notes = result.get("parser_notes", [])
    if notes:
        out.print()
        for note in notes:
            out.print(f"    [dim][*] {note}[/]")
    out.print()


# ─── Diff ─────────────────────────────────────────────────────────────


def display_diff(report: dict) -> None:
    """Format binary diff for human reading."""
    changes = report["function_changes"]
    old_info = report["observed_facts"]["old"]
    new_info = report["observed_facts"]["new"]

    # Header
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", min_width=5)
    grid.add_column()
    old_arch = old_info.get("architecture") or ""
    new_arch = new_info.get("architecture") or ""
    grid.add_row("Old", f"{old_info['path']}  [dim]({old_info['format']} {old_arch})[/]")
    grid.add_row("New", f"{new_info['path']}  [dim]({new_info['format']} {new_arch})[/]")
    out.print(Panel(grid, title="[bold]Binary Diff[/]", border_style="cyan", box=box.ROUNDED))

    # Summary counts
    n_added = len(changes["added"])
    n_removed = len(changes["removed"])
    n_modified = len(changes["modified"])
    n_unchanged = len(changes["unchanged"])

    parts = []
    if n_added:
        parts.append(f"[green]+{n_added} added[/]")
    if n_removed:
        parts.append(f"[red]-{n_removed} removed[/]")
    if n_modified:
        parts.append(f"[yellow]~{n_modified} modified[/]")
    if n_unchanged:
        parts.append(f"[dim]={n_unchanged} unchanged[/]")
    out.print("\n  " + "    ".join(parts))

    # Security Signal Delta
    sig_delta = report.get("security_signals_delta", {})
    if sig_delta.get("has_changes"):
        out.print()
        out.print("[bold yellow]  Security Attack Surface Deltas[/]")
        for item in sig_delta.get("added_categories", []):
            out.print(f"    [green][+][/] [bold]{item['category']:<18}[/] [green]newly introduced[/] ({item.get('rationale', '')})")
        for item in sig_delta.get("expanded_categories", []):
            ev_str = ", ".join(item["newly_observed"][:3])
            out.print(f"    [yellow][~][/] [bold]{item['category']:<18}[/] [yellow]new calls/evidence:[/] {ev_str}")
        for item in sig_delta.get("removed_categories", []):
            out.print(f"    [red][-][/] [bold]{item['category']:<18}[/] [dim]removed[/]")

    # Entitlements Delta
    ent_delta = report.get("entitlements_delta", {})
    if ent_delta.get("has_changes"):
        out.print()
        out.print("[bold cyan]  Entitlements Differential[/]")
        for alert in ent_delta.get("security_alerts", []):
            out.print(f"    [red bold][!][/] [red]{alert}[/]")
        for k, v in ent_delta.get("added", {}).items():
            out.print(f"    [green][+][/] [bold]{k}[/]: [dim]{v}[/]")
        for k, v in ent_delta.get("removed", {}).items():
            out.print(f"    [red][-][/] [bold]{k}[/]: [dim]{v}[/]")
    # Fileset / KEXT changes table (for Mach-O Kernel Collections)
    fileset = report.get("fileset_changes", {})
    if fileset.get("has_fileset") and fileset.get("modified"):
        out.print()
        table = Table(box=box.SIMPLE_HEAD, title="Kernel Extension (KEXT) & Sub-Driver Deltas", title_style="bold cyan", show_lines=False, padding=(0, 1))
        table.add_column("Kernel Extension / Driver", style="bold", min_width=35)
        table.add_column("Size Delta", justify="right")
        table.add_column("Status", justify="center")

        for k in fileset["modified"][:20]:
            delta = k["size_delta_bytes"]
            delta_str = f"+{delta:,} B" if delta > 0 else f"{delta:,} B" if delta < 0 else "0 B"
            delta_style = "green bold" if delta > 0 else "red bold" if delta < 0 else "dim"
            status = "[yellow]code modified[/]" if delta == 0 else "[green]expanded[/]" if delta > 0 else "[red]shrunk[/]"
            table.add_row(k["name"], f"[{delta_style}]{delta_str}[/]", status)

        if len(fileset["modified"]) > 20:
            table.add_row(f"[dim]… +{len(fileset['modified']) - 20} more kernel drivers[/]", "", "")
        out.print(table)

    # Modified functions table
    if changes["modified"]:
        out.print()
        table = Table(box=box.SIMPLE_HEAD, title="Modified Functions", title_style="bold", show_lines=False, padding=(0, 1))
        table.add_column("Function", style="bold", min_width=20)
        table.add_column("Score", justify="center", min_width=5)
        table.add_column("Evidence", style="dim")

        for entry in changes["modified"][:20]:
            score = entry["change_significance"]
            score_style = "red bold" if score >= 60 else "yellow" if score >= 30 else "green"
            name_display = entry.get("demangled_name") or entry["function"]
            ev = entry["evidence"]
            ev_parts = []
            if ev.get("size_delta_bytes"):
                ev_parts.append(f"±{ev['size_delta_bytes']} bytes ({ev.get('size_change_ratio', 0):.0%})")
            if ev.get("calls_added"):
                ev_parts.append(f"+{ev['calls_added']} calls")
            if ev.get("calls_removed"):
                ev_parts.append(f"-{ev['calls_removed']} calls")
            table.add_row(name_display, f"[{score_style}]{score}[/]", ", ".join(ev_parts) or "size unchanged")

        if len(changes["modified"]) > 20:
            table.add_row(f"[dim]… +{len(changes['modified']) - 20} more[/]", "", "")
        out.print(table)

    # Added / removed (compact)
    if changes["added"]:
        out.print()
        names = ", ".join(changes["added"][:15])
        if len(changes["added"]) > 15:
            names += f" (+{len(changes['added']) - 15} more)"
        out.print(f"  [green]Added:[/]   {names}")

    if changes["removed"]:
        names = ", ".join(changes["removed"][:15])
        if len(changes["removed"]) > 15:
            names += f" (+{len(changes['removed']) - 15} more)"
        out.print(f"  [red]Removed:[/] {names}")

    if changes.get("ambiguous_names_not_matched"):
        out.print(f"  [dim][!] {len(changes['ambiguous_names_not_matched'])} functions with duplicate names were not matched[/]")
    out.print()


# ─── LLM Explanation & Security Highlighter ───────────────────────────
from rich.highlighter import RegexHighlighter
from rich.theme import Theme


class SecurityHighlighter(RegexHighlighter):
    """Highlight security concepts, subsystems, versions, and deltas in LLM output."""
    base_style = "sec."
    highlights = [
        r"(?P<section>^(?:SUMMARY|OBSERVATIONS|INTERPRETATION|TECHNICAL INTERPRETATION|EVIDENCE OVERVIEW|ANALYSIS|KEY FINDINGS)[:\s]*$)",
        r"(?P<subsystem>\b(kernelcache(?:\.[a-zA-Z0-9_\-]+)*|kernel|secure_enclave|secure enclave|trustcache|bootloaders?|sep-firmware(?:\.[a-zA-Z0-9_\-]+)*|sep-patches(?:\.[a-zA-Z0-9_\-]+)*|iBoot(?:\.[a-zA-Z0-9_\-]+)*|LLB(?:\.[a-zA-Z0-9_\-]+)*|iBSS(?:\.[a-zA-Z0-9_\-]+)*|iBEC(?:\.[a-zA-Z0-9_\-]+)*|baseband|aopfw(?:\.[a-zA-Z0-9_\-]+)*|cryptex|system_images|other_firmware|manifests)\b)",
        r"(?P<version>\b(iOS\s+\d+\.\d+(?:\.\d+)?|\d+\.\d+\.\d+|\d{2}[A-Z]\d{3}[a-z]?|iPhone\d+,\d+|arm64e?)\b)",
        r"(?P<added>\+\d+\s*(?:bytes|B|KB|MB|added)?\b)",
        r"(?P<removed>-\d+\s*(?:bytes|B|KB|MB|removed)?\b)",
        r"(?P<unchanged>\b(0\s*(?:bytes|B)|unchanged)\b)",
        r"(?P<alert>\b(vulnerability|vulnerabilities|exploit|exploits|patch|patches|bugfix|bugfixes|entitlement|entitlements|sandbox|root_hash|attack surface)\b)",
    ]


security_theme = Theme({
    "sec.section": "bold cyan underline",
    "sec.subsystem": "bold cyan",
    "sec.version": "bold yellow",
    "sec.added": "bold green",
    "sec.removed": "bold red",
    "sec.unchanged": "dim",
    "sec.alert": "bold magenta",
})


def display_explanation_stream(provider: str, model: str, stream: Generator[str, None, None]) -> str:
    """Stream LLM explanation tokens to terminal with live keyword highlighting. Returns accumulated text."""
    import re

    highlighter = SecurityHighlighter()
    console = Console(theme=security_theme, highlight=True)

    out.print()
    out.print(Rule("[bold cyan]LLM Interpretation[/]", style="cyan"))
    out.print()

    full_text = ""
    line_buffer = ""

    def process_and_print_line(raw_line: str) -> None:
        # Strip residual markdown syntax
        clean = re.sub(r"^#{1,6}\s*", "", raw_line)
        clean = re.sub(r"\*\*(.*?)\*\*", r"\1", clean)
        clean = re.sub(r"`(.*?)`", r"\1", clean)

        stripped = clean.strip()
        if re.match(r"^(SUMMARY|OBSERVATIONS|INTERPRETATION|TECHNICAL INTERPRETATION|EVIDENCE OVERVIEW|ANALYSIS|KEY FINDINGS)[:\s]*$", stripped, re.I):
            clean_title = f"{stripped.rstrip(':').upper()}:"
            out.print()
            console.print(highlighter(clean_title))
            return

        console.print(highlighter(clean))

    for chunk in stream:
        full_text += chunk
        line_buffer += chunk
        while "\n" in line_buffer:
            line, line_buffer = line_buffer.split("\n", 1)
            process_and_print_line(line)

    if line_buffer.strip():
        process_and_print_line(line_buffer)

    out.print()
    out.print(Rule(style="cyan"))
    out.print(f"  [dim]Provider: {provider}  │  Model: {model}[/]")
    out.print(f"  [dim]Evidence policy: structured only · no raw binary bytes[/]")
    out.print()
    return full_text


# ─── Providers / Hardware / Recommend ─────────────────────────────────


def display_providers(catalog: list[dict]) -> None:
    """Format provider catalog as a table."""
    table = Table(title="LLM Providers", box=box.ROUNDED, title_style="bold cyan")
    table.add_column("Provider", style="bold")
    table.add_column("Default Model")
    table.add_column("Type", justify="center")
    table.add_column("Endpoint", style="dim", max_width=40)

    for p in catalog:
        ptype = "[green]local[/]" if p["environment_key"] is None else "[magenta]cloud[/]"
        table.add_row(p["name"], p["default_model"], ptype, p["base_url"] or "")

    out.print(table)
    out.print()


def display_hardware(hw: dict) -> None:
    """Format hardware profile."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", min_width=14)
    grid.add_column()

    grid.add_row("System", hw.get("system_model", "Unknown"))
    grid.add_row("OS", hw.get("os", "Unknown"))
    grid.add_row("Form Factor", hw.get("form_factor", "Unknown"))

    cpu = hw.get("cpu", {})
    cores = cpu.get("logical_cores", "?")
    grid.add_row("CPU", f"{cpu.get('name', 'Unknown')} ({cpu.get('architecture', '?')}, {cores} cores)")

    mem = hw.get("memory", {})
    grid.add_row("Memory", f"{mem.get('total_gb', '?')} GB ({mem.get('type', 'system')})")

    for gpu in hw.get("gpus", []):
        vram = f"{gpu['vram_gb']} GB" if gpu.get("vram_gb") else "unknown"
        grid.add_row("GPU", f"{gpu.get('name', 'Unknown')} ({vram}, {gpu.get('memory_type', 'unknown')})")

    cooling = hw.get("cooling", {})
    grid.add_row("Cooling", f"{cooling.get('kind', 'unknown')} ({cooling.get('confidence', '?')} confidence)")

    out.print(Panel(grid, title="[bold]Hardware Profile[/]", border_style="cyan", box=box.ROUNDED))

    for note in hw.get("notes", []):
        out.print(f"    [dim]ℹ  {note}[/]")
    out.print()


def display_recommendation(rec: dict) -> None:
    """Format local model recommendation."""
    model = rec["recommendation"]
    decision = rec["decision"]

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", min_width=14)
    grid.add_column()

    grid.add_row("Recommended", f"[bold green]{model['model']}[/]")
    grid.add_row("Ollama", f"[bold]{model['ollama_model']}[/]")
    grid.add_row("Quantization", model["quantization"])
    grid.add_row("Est. Memory", f"{model['estimated_runtime_memory_gb']} GB")
    grid.add_row("Task Score", f"{model['task_score']}/100")
    grid.add_row("Memory Budget", f"{decision['usable_model_memory_budget_gb']} GB ({decision['budget_basis']})")

    out.print(Panel(grid, title="[bold]Local Model Recommendation[/]", border_style="green", box=box.ROUNDED))
    out.print(f"\n  [bold]Install:[/]  {model['install_command']}\n")

    for constraint in rec.get("constraints", []):
        out.print(f"    [dim]⚠  {constraint}[/]")
    rejected = rec.get("rejected_models", [])
    if rejected:
        out.print(f"    [dim]{len(rejected)} model(s) exceeded the memory budget[/]")
    out.print()


# ─── IPSW ─────────────────────────────────────────────────────────────


def display_ipsw(inventory: dict) -> None:
    """Format IPSW inventory."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", min_width=14)
    grid.add_column()

    grid.add_row("Archive", inventory["path"])
    grid.add_row("Format", inventory.get("archive_format", "ZIP"))
    grid.add_row("Members", str(inventory["member_count"]))

    size_bytes = inventory.get("uncompressed_size_bytes", 0)
    if size_bytes > 1024 ** 3:
        grid.add_row("Uncompressed", f"{size_bytes / 1024 ** 3:.1f} GB")
    elif size_bytes > 1024 ** 2:
        grid.add_row("Uncompressed", f"{size_bytes / 1024 ** 2:.1f} MB")
    else:
        grid.add_row("Uncompressed", f"{size_bytes:,} bytes")

    out.print(Panel(grid, title="[bold]IPSW Inventory[/]", border_style="cyan", box=box.ROUNDED))

    bm = inventory.get("build_manifest")
    if bm and "error" not in bm:
        out.print()
        out.print("  [bold]Build Manifest[/]")
        if bm.get("product_version"):
            out.print(f"    Version:  [bold green]{bm['product_version']}[/] ([bold cyan]{bm.get('product_build_version', '?')}[/])")
        for identity in bm.get("build_identities", [])[:3]:
            device = identity.get("device_class", "?")
            variant = identity.get("variant", "?")
            n_components = len(identity.get("component_paths", []))
            out.print(f"    Target:   [bold]{device}[/] ({variant}) · {n_components} manifest components")

    # Subsystems breakdown
    subsystems = inventory.get("subsystems", {})
    sub_labels = [
        ("kernel", "Kernel Caches"),
        ("secure_enclave", "Secure Enclave (SEP)"),
        ("system_images", "Filesystem & Cryptex Images"),
        ("trust_cache", "Trust Caches"),
        ("bootloaders", "Bootloaders & AOP"),
        ("baseband", "Cellular Baseband"),
        ("accessory_firmware", "Component & Accessory Firmware"),
    ]

    for key, title in sub_labels:
        items = subsystems.get(key, [])
        if items:
            out.print()
            out.print(f"  [bold cyan]{title}[/] ({len(items)} items)")
            for item in items[:6]:
                size = item["size_bytes"]
                size_str = f"{size / 1024 / 1024:7.2f} MB" if size > 1024 * 1024 else f"{size / 1024:7.1f} KB" if size > 1024 else f"{size:7d} B"
                out.print(f"    [dim]{size_str}[/]  [bold]{item['filename']}[/]")
            if len(items) > 6:
                out.print(f"    [dim]… +{len(items) - 6} more {title.lower()}[/]")

    out.print()
    for note in inventory.get("notes", []):
        out.print(f"    [dim][*] {note}[/]")
    out.print()


def display_ipsw_diff(report: dict) -> None:
    """Format IPSW firmware diff for human reading."""
    old_a = report["old_archive"]
    new_a = report["new_archive"]
    build = report["build_changes"]
    comp = report["component_changes"]

    # Header Panel
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", min_width=10)
    grid.add_column()

    old_label = f"iOS {old_a.get('product_version') or '?'} ({old_a.get('build_number') or '?'})"
    new_label = f"iOS {new_a.get('product_version') or '?'} ({new_a.get('build_number') or '?'})"
    grid.add_row("Old IPSW", f"{Path(old_a['path']).name}  [bold magenta]({old_label})[/]")
    grid.add_row("New IPSW", f"{Path(new_a['path']).name}  [bold green]({new_label})[/]")
    out.print(Panel(grid, title="[bold]IPSW Firmware Diff[/]", border_style="cyan", box=box.ROUNDED))

    # Summary Counts
    parts = []
    if comp["total_added"]:
        parts.append(f"[green]+{comp['total_added']} added[/]")
    if comp["total_removed"]:
        parts.append(f"[red]-{comp['total_removed']} removed[/]")
    if comp["total_modified"]:
        parts.append(f"[yellow]~{comp['total_modified']} modified payloads[/]")
    if comp["total_unchanged"]:
        parts.append(f"[dim]={comp['total_unchanged']} unchanged[/]")
    out.print("\n  " + "    ".join(parts))

    # Security Hotspots
    hotspots = report.get("security_hotspots", [])
    if hotspots:
        out.print()
        out.print("  [bold yellow]Modified Security Subsystems:[/] " + ", ".join(f"[bold]{h}[/]" for h in hotspots))

    # Modified Components Table
    modified = comp.get("modified_components", [])
    if modified:
        out.print()
        table = Table(box=box.SIMPLE_HEAD, title="Modified Firmware Components", title_style="bold", show_lines=False, padding=(0, 1))
        table.add_column("Component", style="bold", min_width=30)
        table.add_column("Subsystem", justify="center", style="cyan")
        table.add_column("Size Delta", justify="right")

        for item in modified[:20]:
            delta = item["size_delta_bytes"]
            delta_str = f"+{delta:,} B" if delta > 0 else f"{delta:,} B" if delta < 0 else "0 B"
            delta_style = "green" if delta > 0 else "red" if delta < 0 else "dim"
            table.add_row(item["filename"], item["category"], f"[{delta_style}]{delta_str}[/]")

        if len(modified) > 20:
            table.add_row(f"[dim]… +{len(modified) - 20} more components[/]", "", "")
        out.print(table)

    # Added / Removed components summary
    added_cats = comp.get("added_by_category", {})
    if added_cats:
        out.print()
        for cat, items in added_cats.items():
            names = ", ".join(items[:5])
            if len(items) > 5:
                names += f" (+{len(items) - 5} more)"
            out.print(f"  [green]+ Added ({cat}):[/] {names}")

    removed_cats = comp.get("removed_by_category", {})
    if removed_cats:
        out.print()
        for cat, items in removed_cats.items():
            names = ", ".join(items[:5])
            if len(items) > 5:
                names += f" (+{len(items) - 5} more)"
            out.print(f"  [red]- Removed ({cat}):[/] {names}")

    out.print()


# ─── Config ───────────────────────────────────────────────────────────


def display_config(config: dict) -> None:
    """Format current configuration."""
    from .config import CONFIG_FILE
    from .llm import PROVIDERS

    provider = config.get("provider")
    model = config.get("model")
    default_model = PROVIDERS[provider].default_model if provider and provider in PROVIDERS else "?"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", min_width=14)
    grid.add_column()

    grid.add_row("Provider", provider or "[dim]not set[/]")
    grid.add_row("Model", f"{model or default_model} {'[dim](custom)[/]' if model else '[dim](default)[/]'}")
    if config.get("allow_cloud"):
        grid.add_row("Cloud", "[green]yes[/] — --allow-cloud automatic")
    else:
        grid.add_row("Cloud", "[dim]no — local inference[/]")
    timeout = config.get("timeout")
    grid.add_row("Timeout", f"{timeout}s" if timeout else "[dim]auto[/] (180s local, 90s cloud)")
    grid.add_row("Config File", str(CONFIG_FILE))

    out.print(Panel(grid, title="[bold]Current Configuration[/]", border_style="cyan", box=box.ROUNDED))
    out.print(f"    [dim]Run [bold]poirot setup[/bold] to change defaults.[/]")
    out.print()
