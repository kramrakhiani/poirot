# Code Audit — v0.2.0

## Scope

Full audit of all source modules, tests, CLI, project configuration, and documentation. Reviewed for parser correctness, unsafe resource use, privacy boundaries, output claims, portability, error handling, and maintainability.

## Fixed in this audit

### Bugs
- **`.env` file loading**: API keys in `.env` were silently ignored because nothing loaded the file. Added best-effort `python-dotenv` integration at CLI startup.
- **Endpoint variable reuse**: The `explain()` function duplicated `base_url or provider.base_url` three times across protocol branches instead of using the pre-computed `endpoint` variable. Fixed to use `endpoint` consistently.
- **Zip Slip vulnerability**: `extract_ipsw_component` wrote to user-supplied paths without validating against directory traversal. Added `..` detection in member names and resolved-path checks.
- **Windows CIM parsing**: `_windows_hardware()` queried four CIM classes through a single PowerShell pipeline that produced inconsistent JSON across PowerShell versions. Refactored to query each class individually.
- **Encrypted ZIP crash**: `_build_manifest_summary` did not catch `RuntimeError` from encrypted ZIP entries. Added to the exception handler.

### Robustness
- **CLI error handling**: All commands now catch `ValueError`, `FileNotFoundError`, `OSError`, and `KeyboardInterrupt`. No raw tracebacks are ever shown to users.
- **LLM timeout**: Added `--timeout` CLI flag with sensible defaults (180s local, 90s cloud). Catches `httpx.TimeoutException`, `httpx.HTTPStatusError` (with per-status-code messages for 401 and 429), and `httpx.ConnectError` with actionable suggestions.
- **`--output` behavior**: Previously wrote to both stdout and file. Now writes to file *or* stdout, never both.
- **iOS security signals**: Added five new categories: IPC/XPC, code signing, sandbox, dynamic loading, and Objective-C runtime manipulation. Expanded existing categories with additional iOS-specific terms.

### Project hygiene
- **`.gitignore`**: Created to protect `.env`, `.venv`, `__pycache__`, build artifacts, and IDE files.
- **`pyproject.toml`**: Added pytest config (`pythonpath`, `testpaths`), project URLs, classifiers, keywords, and `python-dotenv` dependency.
- **`--version` flag**: `poirot --version` now works.
- **`__main__.py`**: `python -m poirot` now works.
- **Code style**: Expanded single-line compound statements throughout `cli.py` for readability.

## Remaining MVP limits

- Function matching is exact symbol-name matching only. Stripped binaries and renamed functions need future CFG/instruction-based matching.
- Call graphs and CFG metrics require an additional disassembler backend; they are not inferred by this core parser.
- LIEF parsing is optional and should be tested against a corpus of real Mach-O, ELF, and PE samples before treating it as production-grade coverage.
- Hardware inventory is best-effort because OS and firmware interfaces vary. "Unknown" cooling or VRAM values remain deliberately conservative.
- `_installed_memory_gb()` uses `os.sysconf("SC_PHYS_PAGES")` which is unavailable on macOS; it serves as a Linux-only fallback.

## Verification

The test suite (24 tests) covers:
- Binary-header parsing (PE, Mach-O, ELF)
- Chunk-boundary string extraction
- IPSW ZIP inventory and component extraction
- Zip Slip path-traversal rejection
- Deterministic function diffs
- LLM privacy minimization (no raw binary content in evidence)
- Cloud-consent enforcement
- Provider identification (cloud vs. local)
- Unknown-provider error messages
- All five iOS-specific security signal categories
- False-positive resistance on unrelated strings
- CLI `--version` flag
- Clean error output on missing files (no tracebacks)
