from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from .analysis import analyze_binary, extract_ipsw_component, inspect_ipsw
from .config import is_configured, load_config, run_setup
from .diff import diff_binaries, llm_evidence
from .display import (
    display_analysis,
    display_config,
    display_diff,
    display_explanation_stream,
    display_hardware,
    display_ipsw,
    display_ipsw_diff,
    display_providers,
    display_recommendation,
    spinner,
)
from .ipsw_diff import diff_ipsw, is_ipsw_file, llm_ipsw_evidence
from .llm import (
    PROVIDERS,
    explain,
    explain_stream,
    local_hardware,
    provider_catalog,
    recommend_local_model,
)
from .markdown import generate_markdown_report


def _load_dotenv() -> None:
    """Best-effort .env loading. No hard dependency on python-dotenv."""
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass


def _dump(value: object, output: str | None = None) -> None:
    text = json.dumps(value, indent=2, ensure_ascii=False)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def _print_completion(shell: str) -> None:
    """Output shell completion script."""
    commands = "setup config analyze ipsw ipsw-extract ipsw-diff diff report explain models hardware recommend completion"
    if shell == "bash":
        print(f"""# poirot bash completion
_poirot_completion() {{
    local cur prev opts
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    opts="{commands}"

    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
        return 0
    fi
    COMPREPLY=( $(compgen -f -- "$cur") )
}}
complete -F _poirot_completion poirot
""")
    elif shell == "zsh":
        print(f"""#compdef poirot
# poirot zsh completion
_poirot() {{
    local -a commands
    commands=({commands})
    _arguments \\
        '1: :({commands})' \\
        '*: :_files'
}}
_poirot "$@"
""")
    elif shell == "fish":
        print(f"""# poirot fish completion
for cmd in {commands}
    complete -c poirot -n "__fish_use_subcommand" -a $cmd
end
""")
    else:
        print(f"Unsupported shell: {shell}. Supported: bash, zsh, fish", file=sys.stderr)


def main() -> None:
    _load_dotenv()

    parser = argparse.ArgumentParser(
        prog="poirot",
        description="Poirot — evidence-first binary and iOS firmware investigation.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    commands = parser.add_subparsers(dest="command", required=True)

    # --- setup ---
    commands.add_parser("setup", help="Interactive first-time setup (or reconfigure defaults)")

    # --- config ---
    config_cmd = commands.add_parser("config", help="Show saved defaults configuration")
    config_cmd.add_argument("--json", action="store_true", help="Output as JSON")

    # --- completion ---
    comp_cmd = commands.add_parser("completion", help="Generate shell autocompletion script (bash, zsh, fish)")
    comp_cmd.add_argument("shell", choices=["bash", "zsh", "fish"], default="zsh", nargs="?")

    # --- analyze ---
    analyze = commands.add_parser("analyze", help="Extract structural facts from one binary")
    analyze.add_argument("binary")
    analyze.add_argument("--output", help="Write JSON output to a file instead of stdout")
    analyze.add_argument("--json", action="store_true", help="Output raw JSON to terminal")

    # --- ipsw ---
    ipsw = commands.add_parser("ipsw", help="Inventory an IPSW firmware archive without extracting it")
    ipsw.add_argument("archive")
    ipsw.add_argument("--output", help="Write JSON output to a file instead of stdout")
    ipsw.add_argument("--json", action="store_true", help="Output raw JSON to terminal")

    # --- ipsw-extract ---
    ipsw_extract = commands.add_parser("ipsw-extract", help="Extract one manifest-identified IPSW component")
    ipsw_extract.add_argument("archive")
    ipsw_extract.add_argument("component")
    ipsw_extract.add_argument("output")

    # --- ipsw-diff ---
    ipsw_diff_cmd = commands.add_parser("ipsw-diff", help="Compare two IPSW firmware archives directly")
    ipsw_diff_cmd.add_argument("old")
    ipsw_diff_cmd.add_argument("new")
    ipsw_diff_cmd.add_argument("--component", help="Extract and compare a specific component across both IPSWs")
    ipsw_diff_cmd.add_argument("--filter", "-f", help="Filter functions by name regex")
    ipsw_diff_cmd.add_argument("--min-score", "-s", type=int, help="Only show functions with change score >= N")
    ipsw_diff_cmd.add_argument("--output", help="Write output to a file instead of stdout")
    ipsw_diff_cmd.add_argument("--json", action="store_true", help="Output raw JSON to terminal")

    # --- diff ---
    diff = commands.add_parser("diff", help="Compare two binaries or two IPSWs")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.add_argument("--component", help="For IPSWs: extract and deep-diff a specific component across both archives")
    diff.add_argument("--filter", "-f", help="Filter functions by name regex")
    diff.add_argument("--min-score", "-s", type=int, help="Only show functions with change score >= N")
    diff.add_argument("--output", help="Write output to a file instead of stdout")
    diff.add_argument("--json", action="store_true", help="Output raw JSON to terminal")

    # --- report ---
    report = commands.add_parser("report", help="Write a comparison report (JSON or Markdown)")
    report.add_argument("old")
    report.add_argument("new")
    report.add_argument("--component", help="For IPSWs: extract and report a specific component across both archives")
    report.add_argument("--filter", "-f", help="Filter functions by name regex")
    report.add_argument("--min-score", "-s", type=int, help="Only include functions with change score >= N")
    report.add_argument("--format", choices=["json", "md", "markdown"], default="json", help="Report format (default: json)")
    report.add_argument("--output", help="Write output to a file instead of stdout")

    # --- explain ---
    explain_cmd = commands.add_parser(
        "explain",
        help="Ask an LLM to explain deterministic evidence between binaries or IPSW archives",
    )
    explain_cmd.add_argument("old")
    explain_cmd.add_argument("new")
    explain_cmd.add_argument("--component", help="For IPSWs: extract and explain changes in a specific component")
    explain_cmd.add_argument("--filter", "-f", help="Filter functions by name regex")
    explain_cmd.add_argument("--min-score", "-s", type=int, help="Only include functions with change score >= N")
    explain_cmd.add_argument("--output", help="Write full JSON bundle to a file")
    explain_cmd.add_argument("--json", action="store_true", help="Output raw JSON bundle to terminal")
    explain_cmd.add_argument("--provider", help="Override saved provider (e.g. ollama, openrouter, openai)")
    explain_cmd.add_argument("--model", help="Override the provider's default model")
    explain_cmd.add_argument("--base-url", help="Override the provider's default endpoint URL")
    explain_cmd.add_argument("--timeout", type=int, help="Request timeout in seconds (default: 180 local, 90 cloud)")
    explain_cmd.add_argument("--allow-cloud", action="store_true", default=None, help="Explicitly permit sending compact evidence to a cloud provider")

    # --- info commands ---
    models_cmd = commands.add_parser("models", help="List cloud and local LLM adapters")
    models_cmd.add_argument("--json", action="store_true", help="Output raw JSON to terminal")

    hw_cmd = commands.add_parser("hardware", help="Profile CPU, memory, GPU, and chassis constraints")
    hw_cmd.add_argument("--json", action="store_true", help="Output raw JSON to terminal")

    rec_cmd = commands.add_parser("recommend", help="Profile hardware and recommend a local model")
    rec_cmd.add_argument("--json", action="store_true", help="Output raw JSON to terminal")

    args = parser.parse_args()

    try:
        if args.command == "setup":
            run_setup()
            return

        if args.command == "completion":
            _print_completion(args.shell)
            return

        if args.command == "config":
            config = load_config()
            if getattr(args, "json", False):
                _dump(config)
            else:
                display_config(config)
            return

        if args.command == "models":
            catalog = provider_catalog()
            if getattr(args, "json", False):
                _dump(catalog)
            else:
                display_providers(catalog)
            return

        if args.command == "hardware":
            with spinner("Profiling hardware..."):
                hw = local_hardware()
            if getattr(args, "json", False):
                _dump(hw)
            else:
                display_hardware(hw)
            return

        if args.command == "recommend":
            with spinner("Analyzing hardware constraints..."):
                rec = recommend_local_model()
            if getattr(args, "json", False):
                _dump(rec)
            else:
                display_recommendation(rec)
            return

        if args.command == "analyze":
            with spinner(f"Analyzing {Path(args.binary).name}..."):
                analysis = analyze_binary(args.binary).to_dict()
            if args.output:
                _dump(analysis, args.output)
            elif getattr(args, "json", False):
                _dump(analysis)
            else:
                display_analysis(analysis)
            return

        if args.command == "ipsw":
            with spinner(f"Inspecting {Path(args.archive).name}..."):
                inventory = inspect_ipsw(args.archive)
            if args.output:
                _dump(inventory, args.output)
            elif getattr(args, "json", False):
                _dump(inventory)
            else:
                display_ipsw(inventory)
            return

        if args.command == "ipsw-extract":
            with spinner(f"Extracting {args.component}..."):
                result = extract_ipsw_component(args.archive, args.component, args.output)
            _dump({"extracted_to": str(result)})
            return

        # Check if the inputs are IPSW archives
        is_ipsw_comparison = args.command == "ipsw-diff" or (is_ipsw_file(args.old) and is_ipsw_file(args.new))
        target_component = getattr(args, "component", None)
        filter_pattern = getattr(args, "filter", None)
        min_score = getattr(args, "min_score", None)

        if is_ipsw_comparison and target_component:
            # Component-level drilldown between two IPSWs
            with tempfile.TemporaryDirectory(prefix="poirot_ipsw_") as tmpdir:
                old_extracted = Path(tmpdir) / "old_comp"
                new_extracted = Path(tmpdir) / "new_comp"
                with spinner(f"Extracting {target_component} from both IPSWs..."):
                    extract_ipsw_component(args.old, target_component, str(old_extracted))
                    extract_ipsw_component(args.new, target_component, str(new_extracted))

                with spinner(f"Deep-analyzing {target_component}..."):
                    old_analysis = analyze_binary(str(old_extracted))
                    new_analysis = analyze_binary(str(new_extracted))
                    # Retain original IPSW path context in reports
                    old_analysis.path = f"{Path(args.old).name}:{target_component}"
                    new_analysis.path = f"{Path(args.new).name}:{target_component}"
                    evidence = diff_binaries(
                        old_analysis,
                        new_analysis,
                        filter_pattern=filter_pattern,
                        min_score=min_score,
                    )

                if args.command == "report":
                    if getattr(args, "format", "json") in ("md", "markdown"):
                        md_report = generate_markdown_report(evidence)
                        if args.output:
                            Path(args.output).write_text(md_report + "\n", encoding="utf-8")
                        else:
                            print(md_report)
                    else:
                        _dump(evidence, args.output)
                    return

                if args.command in {"diff", "ipsw-diff"}:
                    if args.output:
                        _dump(evidence, args.output)
                    elif getattr(args, "json", False):
                        _dump(evidence)
                    else:
                        display_diff(evidence)
                    return

                compact_evidence = llm_evidence(evidence)
                is_ipsw_comparison = False  # Output as function binary diff

        elif is_ipsw_comparison:
            # Archive-level firmware comparison
            with spinner("Comparing IPSW firmware archives..."):
                evidence = diff_ipsw(args.old, args.new)

            if args.command == "report":
                if getattr(args, "format", "json") in ("md", "markdown"):
                    md_report = generate_markdown_report(evidence)
                    if args.output:
                        Path(args.output).write_text(md_report + "\n", encoding="utf-8")
                    else:
                        print(md_report)
                else:
                    _dump(evidence, args.output)
                return

            if args.command in {"diff", "ipsw-diff"}:
                if args.output:
                    _dump(evidence, args.output)
                elif getattr(args, "json", False):
                    _dump(evidence)
                else:
                    display_ipsw_diff(evidence)
                return

            compact_evidence = llm_ipsw_evidence(evidence)
        else:
            # Single binary comparison
            with spinner("Comparing binaries..."):
                evidence = diff_binaries(
                    analyze_binary(args.old),
                    analyze_binary(args.new),
                    filter_pattern=filter_pattern,
                    min_score=min_score,
                )

            if args.command == "report":
                if getattr(args, "format", "json") in ("md", "markdown"):
                    md_report = generate_markdown_report(evidence)
                    if args.output:
                        Path(args.output).write_text(md_report + "\n", encoding="utf-8")
                    else:
                        print(md_report)
                else:
                    _dump(evidence, args.output)
                return

            if args.command == "diff":
                if args.output:
                    _dump(evidence, args.output)
                elif getattr(args, "json", False):
                    _dump(evidence)
                else:
                    display_diff(evidence)
                return

            compact_evidence = llm_evidence(evidence)

        # --- explain: merge saved config with CLI flags ---
        config = load_config()

        provider = args.provider or config.get("provider") or "ollama"
        if args.provider and args.provider != config.get("provider"):
            model = args.model or (PROVIDERS.get(provider).default_model if provider in PROVIDERS else None)
        else:
            model = args.model or config.get("model")
        allow_cloud = args.allow_cloud if args.allow_cloud is not None else config.get("allow_cloud", False)
        timeout = args.timeout or config.get("timeout")
        resolved_model = model or (PROVIDERS.get(provider).default_model if provider in PROVIDERS else "default")

        if getattr(args, "json", False):
            with spinner(f"Requesting interpretation from {provider}..."):
                interpretation = explain(
                    compact_evidence,
                    provider,
                    model,
                    args.base_url,
                    allow_cloud=allow_cloud,
                    timeout=timeout,
                )
            bundle = {
                "deterministic_evidence": evidence,
                "llm_evidence": compact_evidence,
                "llm_interpretation": interpretation,
            }
            _dump(bundle, args.output)
        else:
            if is_ipsw_comparison:
                display_ipsw_diff(evidence)
            else:
                display_diff(evidence)

            token_stream = explain_stream(
                compact_evidence,
                provider,
                model,
                args.base_url,
                allow_cloud=allow_cloud,
                timeout=timeout,
            )
            full_text = display_explanation_stream(provider, resolved_model, token_stream)

            if args.output:
                interpretation = {
                    "kind": "llm_interpretation",
                    "provider": provider,
                    "model": resolved_model,
                    "input_policy": "structured evidence only; no raw binary bytes",
                    "explanation": full_text,
                }
                bundle = {
                    "deterministic_evidence": evidence,
                    "llm_evidence": compact_evidence,
                    "llm_interpretation": interpretation,
                }
                _dump(bundle, args.output)

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except OSError as exc:
        print(f"I/O error: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
