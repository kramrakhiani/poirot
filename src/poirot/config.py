# Persistent user configuration for Poirot.
# Stores defaults in ~/.poirot/config.json so that `poirot explain old new`
# works after a one-time `poirot setup`.
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

CONFIG_DIR = Path.home() / ".poirot"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULTS = {
    "provider": None,
    "model": None,
    "allow_cloud": False,
    "timeout": None,
}


def _load_raw() -> dict[str, Any]:
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def load_config() -> dict[str, Any]:
    # Load config from ~/.poirot/config.json, filling missing keys with defaults
    saved = _load_raw()
    return {**DEFAULTS, **saved}


def save_config(config: dict[str, Any]) -> Path:
    # Write config to disk; creates ~/.poirot/ if needed
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return CONFIG_FILE


def is_configured() -> bool:
    # True if the user has completed poirot setup at least once
    config = _load_raw()
    return config.get("provider") is not None


def run_setup() -> dict[str, Any]:
    # Interactive first-run wizard returning the saved configuration dictionary
    from .llm import PROVIDERS, CLOUD_PROVIDERS

    print("\n╭─────────────────────────────────────────╮")
    print("│     Poirot — First-Time Setup           │")
    print("╰─────────────────────────────────────────╯\n")

    # Step 1: Local vs Cloud
    print("How do you want to run LLM explanations?\n")
    print("  1) Local  — Ollama, LM Studio, or llama.cpp (private, no API key needed)")
    print("  2) Cloud  — OpenAI, Anthropic, Google, OpenRouter, etc. (requires API key)")
    print()

    mode = _ask_choice("Choose [1/2]: ", {"1", "2"})
    is_cloud = mode == "2"

    # Step 2: Pick provider
    if is_cloud:
        cloud_list = sorted(CLOUD_PROVIDERS)
        print(f"\nAvailable cloud providers: {', '.join(cloud_list)}\n")
        for i, name in enumerate(cloud_list, 1):
            p = PROVIDERS[name]
            print(f"  {i}) {name:<12}  (default model: {p.default_model})")
        print()
        idx = _ask_choice(
            f"Choose [1-{len(cloud_list)}]: ",
            {str(i) for i in range(1, len(cloud_list) + 1)},
        )
        provider = cloud_list[int(idx) - 1]
    else:
        local_list = [name for name in PROVIDERS if name not in CLOUD_PROVIDERS]
        print(f"\nAvailable local providers: {', '.join(local_list)}\n")
        for i, name in enumerate(local_list, 1):
            p = PROVIDERS[name]
            print(f"  {i}) {name:<12}  (endpoint: {p.base_url})")
        print()
        idx = _ask_choice(
            f"Choose [1-{len(local_list)}]: ",
            {str(i) for i in range(1, len(local_list) + 1)},
        )
        provider = local_list[int(idx) - 1]

    # Step 3: Model override
    default_model = PROVIDERS[provider].default_model
    print(f"\nDefault model for {provider}: {default_model}")
    custom = input("Press Enter to keep it, or type a model name: ").strip()
    model = custom or None

    # Step 4: API key check for cloud
    if is_cloud:
        env_key = PROVIDERS[provider].environment_key
        current_value = os.environ.get(env_key or "")
        if current_value:
            print(f"\n[+] {env_key} is already set in your environment.")
        else:
            print(f"\n[!] {env_key} is not set.")
            print(f"  Add it to your .env file or export it in your shell:")
            print(f"  echo '{env_key}=your-key-here' >> .env\n")

    # Step 5: Save
    config = {
        "provider": provider,
        "model": model,
        "allow_cloud": is_cloud,
        "timeout": None,
    }
    path = save_config(config)

    print(f"\n[+] Configuration saved to {path}")
    print(f"  Provider:    {provider}")
    print(f"  Model:       {model or default_model} {'(custom)' if model else '(default)'}")
    print(f"  Cloud:       {'yes (--allow-cloud is enabled)' if is_cloud else 'no (local inference)'}")
    print(f"\n  Run:             poirot explain old.bin new.bin")
    print(f"  To reconfigure:  poirot setup\n")

    return config


def _ask_choice(prompt: str, valid: set[str]) -> str:
    # Keep asking until the user inputs a valid option
    while True:
        try:
            answer = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSetup cancelled.")
            raise SystemExit(130)
        if answer in valid:
            return answer
        print(f"  Please enter one of: {', '.join(sorted(valid))}")
