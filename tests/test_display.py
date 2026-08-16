import io
from unittest.mock import patch

from poirot.display import (
    display_analysis,
    display_diff,
    display_explanation_stream,
    display_hardware,
    display_ipsw,
    display_providers,
    display_recommendation,
)


def test_display_analysis_runs_without_error():
    sample = {
        "path": "/usr/bin/sample",
        "format": "Mach-O 64-bit",
        "architecture": "arm64",
        "entry_point": 0x100004000,
        "executable_sections": ["__text"],
        "imports": ["_printf"],
        "exports": ["_main"],
        "functions": [{"name": "_main", "size": 32}],
        "strings": ["Hello"],
        "security_signals": [{"category": "networking", "evidence": ["https://"], "rationale": "Network test"}],
        "parser_notes": ["Parsed securely."],
    }
    # Capture console output
    with patch("sys.stdout", new=io.StringIO()):
        display_analysis(sample)


def test_display_diff_runs_without_error():
    sample = {
        "observed_facts": {
            "old": {"path": "old.bin", "format": "Mach-O", "architecture": "arm64"},
            "new": {"path": "new.bin", "format": "Mach-O", "architecture": "arm64"},
        },
        "function_changes": {
            "added": ["new_func"],
            "removed": ["old_func"],
            "modified": [
                {
                    "function": "auth_check",
                    "change_significance": 80,
                    "evidence": {"size_delta_bytes": 128, "calls_added": 2, "calls_removed": 0},
                }
            ],
            "unchanged": ["helper"],
            "ambiguous_names_not_matched": [],
        },
    }
    with patch("sys.stdout", new=io.StringIO()):
        display_diff(sample)


def test_display_explanation_stream():
    def dummy_stream():
        yield "This "
        yield "is "
        yield "evidence."

    with patch("sys.stdout", new=io.StringIO()) as out:
        result = display_explanation_stream("openrouter", "claude-sonnet-4", dummy_stream())
        assert result == "This is evidence."


def test_display_hardware_and_recommendation():
    hw = {
        "system_model": "MacBook Pro",
        "os": "macOS 15.0",
        "form_factor": "laptop",
        "cpu": {"name": "Apple M3", "architecture": "arm64", "logical_cores": 12},
        "memory": {"total_gb": 36.0, "type": "unified"},
        "gpus": [{"name": "Apple integrated GPU", "vram_gb": 36.0, "memory_type": "unified"}],
        "cooling": {"kind": "active", "confidence": "high"},
    }
    rec = {
        "hardware": hw,
        "decision": {"usable_model_memory_budget_gb": 22.3, "budget_basis": "62% unified memory"},
        "recommendation": {
            "model": "Qwen2.5-Coder 14B Instruct",
            "ollama_model": "qwen2.5-coder:14b",
            "quantization": "Q5_K_M",
            "estimated_runtime_memory_gb": 13.5,
            "install_command": "ollama pull qwen2.5-coder:14b",
            "task_score": 93,
        },
    }
    with patch("sys.stdout", new=io.StringIO()):
        display_hardware(hw)
        display_recommendation(rec)
        display_providers([{"name": "ollama", "default_model": "qwen2.5-coder:7b", "environment_key": None, "base_url": "http://localhost:11434/v1"}])
        display_ipsw({"path": "sample.ipsw", "member_count": 10, "uncompressed_size_bytes": 1000000})
