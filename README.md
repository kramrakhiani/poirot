# Poirot

```
  ██████╗  ██████╗ ██╗██████╗  ██████╗ ████████╗
  ██╔══██╗██╔═══██╗██║██╔══██╗██╔═══██╗╚══██╔══╝
  ██████╔╝██║   ██║██║██████╔╝██║   ██║   ██║   
  ██╔═══╝ ██║   ██║██║██╔══██╗██║   ██║   ██║   
  ██║     ╚██████╔╝██║██║  ██║╚██████╔╝   ██║   
  ╚═╝      ╚═════╝ ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   
```

Poirot is an evidence-first developer and security tool for structural binary comparison and Apple IPSW firmware differential analysis. It extracts deterministic structural facts from compiled binaries (Mach-O, ELF, PE) and firmware archives (IPSW), identifies modified functions and payloads, calculates change significance scores, and optionally queries an LLM to generate plain-text interpretations grounded strictly in extracted evidence.

Analysis is performed locally through static parsers. When an LLM explanation is requested, Poirot generates a minimal, privacy-bounded JSON evidence bundle containing only structural metadata and delta summaries. Raw binary bytes, disassembly, paths, and complete symbol tables are excluded.

## Installation

```bash
# Core CLI with binary structure and LLM support
python -m pip install -e '.[analysis,llm]'

# For development and running the test suite
python -m pip install -e '.[analysis,llm,dev]'
```

### Dependencies

- **Core**: Python >= 3.10, `rich` (CLI terminal UI)
- **`analysis` extra**: `lief` (section analysis, imports, exports, symbol/function recovery), `lzfse` (Apple Image4/kernelcache decompression)
- **`llm` extra**: `httpx` (local and cloud REST clients), `python-dotenv` (`.env` key loading)
- **`dev` extra**: `pytest`

## Quick Start

### 1. Configure Provider Defaults

Run the one-time interactive setup to choose a default LLM provider (local runtime or cloud endpoint):

```bash
poirot setup
```

Configuration is stored in `~/.poirot/config.json`. You can inspect the current settings at any time with:

```bash
poirot config
```

If using a cloud provider, export the appropriate environment variable or place it in a `.env` file in your working directory (e.g., `NVIDIA_API_KEY`, `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `DEEPSEEK_API_KEY`, `GROQ_API_KEY`).

### 2. Inspect a Binary

```bash
poirot analyze /path/to/binary
```

Extracts binary format, target architecture, entry point, executable sections, symbols, extracted printable strings, and heuristic security triage signals (e.g., XPC, keychain, code signing, cryptography). Automatically unwraps Apple Image4 (`IM4P`/`IMG4`) compressed containers.

### 3. Compare Binaries

```bash
# Terminal table comparing added, removed, and modified functions
poirot diff old_binary new_binary

# Filter functions by regex pattern or minimum change score
poirot diff old_binary new_binary --filter "auth|token" --min-score 30

# Export report as JSON or GitHub-flavored Markdown
poirot report old_binary new_binary --format md --output diff_report.md
poirot report old_binary new_binary --format json --output diff_report.json
```

Diffing automatically:
- Demangles C++ and Swift symbols for readable function tables.
- Extracts and diffs embedded XML/DER entitlements (flagging newly added private entitlements or sandbox exceptions).
- Diffs modern Mach-O Kernel Collections (`MH_FILESET`) down to individual kernel extensions (KEXTs) and drivers.
- Highlights changes to attack surface (newly linked IPC/XPC, crypto, or keychain APIs).

### 4. Explain Differences via LLM

```bash
# Streams plain-text explanation with live security highlighting using default provider
poirot explain old_binary new_binary

# Focus explanation on specific subsystems or functions
poirot explain old_binary new_binary --filter "auth" --min-score 40

# Override provider or model on the command line
poirot explain old_binary new_binary --provider nvidia --allow-cloud
poirot explain old_binary new_binary --provider ollama --model qwen2.5-coder:7b
poirot explain old_binary new_binary --provider openrouter --allow-cloud
```

## Apple IPSW Firmware Analysis

Poirot operates on Apple IPSW firmware archives directly without requiring macOS, Xcode, or multi-gigabyte disk extractions.

### Firmware Differential Analysis

Compare two IPSW releases to identify build differences and modified subsystem components:

```bash
poirot diff iOS_18.0.ipsw iOS_18.1.ipsw
poirot explain iOS_18.0.ipsw iOS_18.1.ipsw --allow-cloud
```

The tool compares `BuildManifest.plist` records (product versions, build versions, supported boards) and categorizes component changes across subsystems:

- **Kernel**: `kernelcache.release.*` (automatically unwraps IM4P / LZFSE and diffs fileset KEXTs)
- **Secure Enclave**: `sep-firmware.img4`, `sep-patches.im4p`
- **Cryptex and System Images**: Cryptex OS DMGs, App DMGs, system filesystem bundles
- **TrustCache**: Static and personalization trust caches
- **Bootloaders**: `iBoot`, `LLB`, `iBSS`, `iBEC`, `AOP`
- **Baseband**: Cellular modem firmware (`.bbfw`, `.fls`)

### Component-Level IPSW Comparison

To deep-diff a specific binary between two IPSWs without extracting the rest of the archive:

```bash
poirot diff old.ipsw new.ipsw --component "kernelcache.release.iPhone16"
poirot explain old.ipsw new.ipsw --component "kernelcache.release.iPhone16" --allow-cloud
```

### IPSW Inventory and Extraction

```bash
# Inventory manifest entries and Mach-O candidates inside an IPSW
poirot ipsw firmware.ipsw

# Extract a specific component securely
poirot ipsw-extract firmware.ipsw "kernelcache.release.iPhone16" ./kernelcache_out
```

## Supported Providers

| Provider | Protocol | Default Model | Key Variable |
| :--- | :--- | :--- | :--- |
| `nvidia` | OpenAI-compatible | `meta/llama-3.1-8b-instruct` | `NVIDIA_API_KEY` |
| `openrouter` | OpenAI-compatible | `anthropic/claude-sonnet-4` | `OPENROUTER_API_KEY` |
| `openai` | OpenAI | `gpt-5` | `OPENAI_API_KEY` |
| `anthropic` | Anthropic Messages | `claude-sonnet-5` | `ANTHROPIC_API_KEY` |
| `google` | Google Gemini REST | `gemini-2.5-pro` | `GOOGLE_API_KEY` |
| `deepseek` | OpenAI-compatible | `deepseek-reasoner` | `DEEPSEEK_API_KEY` |
| `groq` | OpenAI-compatible | `llama-3.3-70b-versatile` | `GROQ_API_KEY` |
| `ollama` | OpenAI-compatible | `qwen2.5-coder:7b` | None (local) |
| `local` | OpenAI-compatible | `Qwen2.5-Coder-7B-Instruct` | None (local) |

List registered provider adapters with:

```bash
poirot models
```

## Hardware Profiling and Model Selection

Poirot profiles host hardware to recommend appropriate local model sizes for binary explanation tasks:

```bash
# Inspect CPU architecture, logical cores, memory, GPU VRAM, and thermal profile
poirot hardware

# Calculate safe local memory budget and recommend optimal Ollama model
poirot recommend
```

The recommendation engine reserves system RAM headroom, distinguishes Apple Silicon unified memory from dedicated discrete VRAM, and factors in chassis thermal constraints (e.g., fanless systems).

## Security and Privacy Model

1. **Deterministic Separation**: Structural analysis is strictly separated from LLM interpretations.
2. **Minimal Cloud Data Transfer**: Cloud requests transmit only structured change summaries (function names, call count deltas, size deltas, security signal categories). Raw binary bytes, string dumps, and full symbol lists are never transmitted.
3. **Explicit Cloud Consent**: Cloud requests require `--allow-cloud` (configured automatically via `poirot setup` or passed explicitly).
4. **Path Traversal Guards**: IPSW member extraction validates against directory traversal (Zip Slip) vulnerabilities.
5. **No Hallucinated Findings**: System prompts instruct LLMs to treat provided JSON evidence as the sole source of truth and cite exact fields.

## CLI Reference

```
poirot --version                                      Show program version
poirot setup                                          Interactive first-time configuration wizard
poirot config [--json]                                Display current saved defaults
poirot analyze <binary> [--json] [--output]           Extract binary metadata and security signals
poirot diff <old> <new> [-f PATTERN] [-s MIN_SCORE]   Compare two binaries or two IPSW archives
poirot diff <old> <new> --component <path>            Deep-diff a specific payload inside two IPSWs
poirot ipsw <archive.ipsw> [--output]                 Inventory IPSW firmware archive
poirot ipsw-extract <ipsw> <member> <out>             Extract a single component from an IPSW
poirot ipsw-diff <old.ipsw> <new.ipsw>                Explicit IPSW firmware comparison
poirot report <old> <new> [--format md|json] [-o OUT] Generate Markdown or JSON diff report
poirot explain <old> <new> [-f PATTERN] [-s SCORE]    Stream LLM explanation of differences
poirot models [--json]                                List registered LLM provider adapters
poirot hardware [--json]                              Display host hardware capabilities
poirot recommend [--json]                             Recommend local model for host hardware
poirot completion [bash|zsh|fish]                     Generate shell autocompletion script
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## License

MIT License. See `LICENSE` for details.
