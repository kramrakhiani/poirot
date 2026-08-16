from __future__ import annotations

import json
import os
import platform
import re
import subprocess
from urllib.parse import urlparse
from dataclasses import asdict, dataclass
from typing import Generator


@dataclass(frozen=True)
class Provider:
    name: str
    default_model: str
    environment_key: str | None
    base_url: str | None
    protocol: str


PROVIDERS = {
    "openai": Provider("openai", "gpt-5", "OPENAI_API_KEY", "https://api.openai.com/v1", "openai"),
    "anthropic": Provider("anthropic", "claude-sonnet-5", "ANTHROPIC_API_KEY", "https://api.anthropic.com/v1", "anthropic"),
    "google": Provider("google", "gemini-2.5-pro", "GOOGLE_API_KEY", "https://generativelanguage.googleapis.com/v1beta", "google"),
    "nvidia": Provider("nvidia", "meta/llama-3.1-8b-instruct", "NVIDIA_API_KEY", "https://integrate.api.nvidia.com/v1", "openai"),
    "deepseek": Provider("deepseek", "deepseek-reasoner", "DEEPSEEK_API_KEY", "https://api.deepseek.com/v1", "openai"),
    "groq": Provider("groq", "llama-3.3-70b-versatile", "GROQ_API_KEY", "https://api.groq.com/openai/v1", "openai"),
    "openrouter": Provider("openrouter", "anthropic/claude-sonnet-4", "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1", "openai"),
    "ollama": Provider("ollama", "qwen2.5-coder:7b", None, "http://localhost:11434/v1", "openai"),
    "local": Provider("local", "Qwen2.5-Coder-7B-Instruct", None, "http://localhost:1234/v1", "openai"),
}

CLOUD_PROVIDERS = frozenset(name for name, p in PROVIDERS.items() if p.environment_key)


def provider_catalog() -> list[dict]:
    return [asdict(provider) for provider in PROVIDERS.values()]


def _run(command: list[str]) -> str | None:
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL, timeout=4).strip() or None
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def _gb(value: str | None) -> float | None:
    try:
        return round(int(value or "") / 1024**3, 1)
    except ValueError:
        return None


def _installed_memory_gb() -> float | None:
    # os.sysconf("SC_PHYS_PAGES") is not available on macOS; this function
    # serves as a last-resort fallback and will only succeed on Linux.
    try:
        return round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1024**3, 1)
    except (AttributeError, ValueError, OSError):
        return None


def _linux_value(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as file:
            return file.read().strip() or None
    except OSError:
        return None


def _mac_hardware() -> dict:
    model = _run(["sysctl", "-n", "hw.model"])
    profile = _run(["system_profiler", "SPHardwareDataType"])
    model_name = None
    chip = None
    if profile:
        name_match = re.search(r"Model Name:\s*(.+)", profile)
        chip_match = re.search(r"Chip:\s*(.+)", profile)
        model_name = name_match.group(1).strip() if name_match else None
        chip = chip_match.group(1).strip() if chip_match else None
    if not model and profile:
        match = re.search(r"Model Identifier:\s*(.+)", profile)
        model = match.group(1).strip() if match else None
    memory = _gb(_run(["sysctl", "-n", "hw.memsize"])) or _installed_memory_gb()
    cpu = chip or _run(["sysctl", "-n", "machdep.cpu.brand_string"]) or platform.processor() or "unknown"
    # Apple Silicon reports GPU capacity as shared unified memory, not VRAM.
    apple_silicon = platform.machine() == "arm64"
    laptop = bool((model_name and "MacBook" in model_name) or (model and "MacBook" in model))
    fanless = bool(
        (model_name and model_name.startswith("MacBook Air"))
        or (model and model.startswith("MacBookAir"))
    )
    if fanless:
        cooling = {"kind": "fanless", "confidence": "high", "signal": "MacBook Air model family"}
    elif model_name and ("MacBook Pro" in model_name or model_name in {"Mac mini", "Mac Studio", "Mac Pro", "iMac"}):
        cooling = {"kind": "active", "confidence": "medium", "signal": "MacBook Pro or desktop model family"}
    else:
        cooling = {"kind": "unknown", "confidence": "low", "signal": "No cooling inventory exposed"}
    return {
        "system_model": " / ".join(part for part in (model_name, model) if part) or "Mac (model unavailable)",
        "form_factor": "laptop" if laptop else "desktop" if model else "unknown",
        "cooling": cooling,
        "cpu": {"name": cpu, "architecture": platform.machine(), "logical_cores": os.cpu_count()},
        "memory": {"total_gb": memory, "type": "unified" if apple_silicon else "system"},
        "gpus": [{"name": "Apple integrated GPU" if apple_silicon else "GPU unavailable", "vram_gb": memory if apple_silicon else None, "memory_type": "unified" if apple_silicon else "unknown"}],
        "notes": ["Apple Silicon shares RAM between CPU and GPU; there is no separate VRAM pool."] if apple_silicon else [],
    }


def _linux_hardware() -> dict:
    cpuinfo = _linux_value("/proc/cpuinfo") or ""
    cpu_name = next(
        (line.split(":", 1)[1].strip() for line in cpuinfo.splitlines()
         if line.lower().startswith(("model name", "hardware"))),
        platform.processor() or "unknown",
    )
    meminfo = _linux_value("/proc/meminfo") or ""
    match = re.search(r"MemTotal:\s+(\d+) kB", meminfo)
    memory = round(int(match.group(1)) / 1024**2, 1) if match else None
    model = _linux_value("/sys/class/dmi/id/product_name")
    chassis = _linux_value("/sys/class/dmi/id/chassis_type")
    battery = bool(_run(["sh", "-c", "test -d /sys/class/power_supply/BAT* && echo yes"]))
    laptop = battery or chassis in {"8", "9", "10", "14"}
    gpus: list[dict] = []
    nvidia = _run(["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"])
    if nvidia:
        for row in nvidia.splitlines():
            parts = [part.strip() for part in row.split(",")]
            if len(parts) >= 2:
                name, vram = parts[0], parts[1]
                driver = parts[2] if len(parts) > 2 else None
                gpus.append({"name": name, "vram_gb": round(float(vram) / 1024, 1), "memory_type": "dedicated", "driver": driver})
    else:
        pci = _run(["lspci"])
        if pci:
            gpus = [
                {"name": line.split(": ", 1)[-1], "vram_gb": None, "memory_type": "unknown"}
                for line in pci.splitlines()
                if re.search(r"VGA|3D controller|Display", line, re.I)
            ]
    # Absence of hwmon fan files is inconclusive; many laptops hide them from Linux.
    fan_sensors: list[str] = []
    try:
        for directory in os.listdir("/sys/class/hwmon"):
            fan_sensors.extend(
                name for name in os.listdir(f"/sys/class/hwmon/{directory}")
                if name.startswith("fan") and name.endswith("_input")
            )
    except OSError:
        pass
    if fan_sensors:
        cooling = {"kind": "active", "confidence": "high", "signal": f"{len(fan_sensors)} fan sensor(s) exposed by hwmon"}
    else:
        cooling = {"kind": "unknown", "confidence": "low", "signal": "No fan sensor exposed; this does not prove fanless operation"}
    return {
        "system_model": model or "Linux system (model unavailable)",
        "form_factor": "laptop" if laptop else "desktop_or_server",
        "cooling": cooling,
        "cpu": {"name": cpu_name, "architecture": platform.machine(), "logical_cores": os.cpu_count()},
        "memory": {"total_gb": memory or _installed_memory_gb(), "type": "system"},
        "gpus": gpus,
        "notes": [],
    }


def _windows_hardware() -> dict:
    # Query each CIM class individually to avoid PowerShell JSON-merge issues
    # across versions and system configurations.
    def _cim(class_name: str) -> list[dict]:
        raw = _run([
            "powershell", "-NoProfile", "-Command",
            f"Get-CimInstance {class_name} | Select-Object * | ConvertTo-Json -Depth 3",
        ])
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return parsed if isinstance(parsed, list) else [parsed]

    systems = _cim("Win32_ComputerSystem")
    cpus = _cim("Win32_Processor")
    video_controllers = _cim("Win32_VideoController")
    fans = _cim("Win32_Fan")

    system = systems[0] if systems else {}
    cpu = cpus[0] if cpus else {}
    gpus = [
        {"name": item.get("Name"), "vram_gb": _gb(str(item.get("AdapterRAM", ""))), "memory_type": "dedicated_or_shared"}
        for item in video_controllers
        if item.get("AdapterRAM")
    ]
    if fans:
        cooling = {"kind": "active", "confidence": "medium", "signal": "Win32_Fan reports an installed fan"}
    else:
        cooling = {"kind": "unknown", "confidence": "low", "signal": "Win32_Fan has no data; vendor firmware often does not expose fan sensors"}
    return {
        "system_model": system.get("Model", "Windows system (model unavailable)"),
        "form_factor": "laptop" if system.get("PCSystemType") == 2 else "desktop_or_server",
        "cooling": cooling,
        "cpu": {
            "name": cpu.get("Name", "unknown"),
            "architecture": platform.machine(),
            "cores": cpu.get("NumberOfCores"),
            "logical_cores": cpu.get("NumberOfLogicalProcessors"),
        },
        "memory": {"total_gb": _gb(str(system.get("TotalPhysicalMemory", ""))), "type": "system"},
        "gpus": gpus,
        "notes": ["Windows drivers may report shared graphics memory as AdapterRAM; verify dedicated VRAM in the GPU vendor utility."],
    }


def local_hardware() -> dict:
    system = platform.system()
    details = _mac_hardware() if system == "Darwin" else _windows_hardware() if system == "Windows" else _linux_hardware()
    details.update({"os": platform.platform(), "platform": system, "profiler_version": 2})
    return details


EXPLANATION_TASK = "Explain deterministic binary-diff evidence and cite the supporting fields."

# Scores are specific to Poirot's fixed task. This is not a generic chatbot
# ranking: code/symbol literacy and disciplined evidence explanation matter most.
MODEL_CATALOG = [
    {"model": "Qwen2.5-Coder 3B Instruct", "ollama_model": "qwen2.5-coder:3b", "parameters_b": 3, "family": "Qwen Coder", "task_score": 76},
    {"model": "Qwen2.5-Coder 7B Instruct", "ollama_model": "qwen2.5-coder:7b", "parameters_b": 7, "family": "Qwen Coder", "task_score": 89},
    {"model": "Qwen2.5-Coder 14B Instruct", "ollama_model": "qwen2.5-coder:14b", "parameters_b": 14, "family": "Qwen Coder", "task_score": 93},
    {"model": "Qwen2.5-Coder 32B Instruct", "ollama_model": "qwen2.5-coder:32b", "parameters_b": 32, "family": "Qwen Coder", "task_score": 96},
    {"model": "Llama 3.1 8B Instruct", "ollama_model": "llama3.1:8b", "parameters_b": 8, "family": "Llama", "task_score": 78},
    {"model": "Mistral Small 3.1 Instruct", "ollama_model": "mistral-small3.1", "parameters_b": 24, "family": "Mistral", "task_score": 82},
    {"model": "DeepSeek-R1-Distill-Qwen 7B", "ollama_model": "deepseek-r1:7b", "parameters_b": 7, "family": "DeepSeek R1 Distill", "task_score": 74},
    {"model": "DeepSeek-R1-Distill-Qwen 14B", "ollama_model": "deepseek-r1:14b", "parameters_b": 14, "family": "DeepSeek R1 Distill", "task_score": 78},
]


def _model_memory_gb(parameters_b: int, quantization: str, context_tokens: int = 8192) -> float:
    bits = {"Q4_K_M": 4.8, "Q5_K_M": 5.7}[quantization]
    # Weight storage alone is misleading; reserve workspace and KV-cache headroom.
    return round(parameters_b * bits / 8 + max(1.5, parameters_b * 0.08) + context_tokens / 8192 * min(2.5, parameters_b * 0.06), 1)


def recommend_local_model() -> dict:
    hardware = local_hardware()
    memory = hardware["memory"]["total_gb"] or 8
    dedicated = max((gpu.get("vram_gb") or 0 for gpu in hardware["gpus"] if gpu.get("memory_type") == "dedicated"), default=0)
    unified = hardware["memory"]["type"] == "unified"
    fanless = hardware.get("cooling", {}).get("kind") == "fanless"
    # Dedicated VRAM is the limiting fast-inference resource; otherwise reserve
    # enough system/unified memory for the OS and the local runtime.
    budget = dedicated * 0.78 if dedicated else memory * (0.50 if fanless else 0.62 if unified else 0.45)
    quantization = "Q4_K_M" if budget < 20 or fanless else "Q5_K_M"
    feasible = [entry for entry in MODEL_CATALOG if _model_memory_gb(entry["parameters_b"], quantization) <= budget]
    # Larger parameter counts only break ties; task-specific capability leads.
    selected = max(feasible or [MODEL_CATALOG[0]], key=lambda entry: (entry["task_score"], entry["parameters_b"]))
    constraints = ["Fanless chassis: capped the recommendation to protect sustained performance."] if fanless else []
    if hardware.get("cooling", {}).get("kind") == "unknown":
        constraints.append("Cooling capacity is unknown, so this recommendation targets moderate sustained workloads.")
    if dedicated:
        constraints.append(f"Dedicated GPU VRAM is the primary inference budget ({dedicated} GB).")
    elif unified:
        constraints.append("Unified memory is shared with the OS and applications; substantial headroom is reserved.")
    else:
        constraints.append("No measurable dedicated VRAM; model is selected for CPU/offloaded inference.")
    rejected = [{"model": entry["model"], "reason": "does not fit the safe memory budget"} for entry in MODEL_CATALOG if entry not in feasible]
    return {
        "task": EXPLANATION_TASK,
        "hardware": hardware,
        "decision": {
            "usable_model_memory_budget_gb": round(budget, 1),
            "budget_basis": "78% dedicated VRAM" if dedicated else "50% RAM for fanless systems" if fanless else "62% unified memory" if unified else "45% system RAM",
            "selection_policy": "Choose the highest task score among models that fit the safe sustained-use memory budget. Parameter count breaks ties only.",
        },
        "recommendation": {
            **selected,
            "quantization": quantization,
            "estimated_runtime_memory_gb": _model_memory_gb(selected["parameters_b"], quantization),
            "install_command": f"ollama pull {selected['ollama_model']}",
            "rationale": "Highest-scoring safe model for Poirot's fixed evidence-explanation task; no user model choice is required.",
        },
        "rejected_models": rejected,
        "constraints": constraints,
        "note": "The catalog compares code-focused, general-instruction, and reasoning-distilled families. Estimates include an 8k context allowance; context length, GPU offload, and other applications change actual requirements.",
    }


SYSTEM_PROMPT = """You are a senior reverse engineering and firmware security researcher explaining binary-diff and firmware differential analysis evidence in a UNIX terminal.

STRUCTURE YOUR OUTPUT INTO THREE CLEAR SECTIONS:

EVIDENCE OVERVIEW:
Briefly summarize the target comparison scope (firmware builds/versions or binary paths, architectures, and primary scope of change).

OBSERVATIONS:
List the key deterministic findings extracted from the evidence. Directly cite specific component names, subsystems, size deltas (in bytes/MB), and counts (added, removed, modified, unchanged).

TECHNICAL INTERPRETATION:
Provide senior reverse-engineering analysis explaining WHY these specific components and subsystems were modified, their architectural roles, and what the evidence indicates technically:
- Role & Impact: Explain the function of each modified component (e.g., XNU kernel, SEP firmware, iBoot bootloader, TrustCache) and what changes to it mean for the operating system.
- Kernel Extensions & Drivers: If kernel module changes or KEXTs are present (e.g., AppleUVDMDriver, AppleT8130CLPC, CoreTrust, IOGPUFamily), explain their specific domain (e.g. display/video processing, CPU/GPU power control, code-signing verification, graphics acceleration) and the purpose of the patch.
- Scope of Change: Analyze the magnitude of modifications (e.g., a small size delta of ~100-300 bytes in a driver indicates a focused bugfix or logic patch in an existing routine/driver rather than an architectural subsystem overhaul).
- Subsystem Relationships: Explain how related components interact (e.g., why TrustCaches and DMG root hashes are regenerated alongside system image updates).
- Unchanged Components: Note the significance of critical security components that remained unchanged (e.g., unchanged SEP or LLB proves that Secure Enclave boot trust and cryptographic hardware routines were not altered in this release).

FORMATTING:
- Output plain terminal text (do NOT use markdown syntax like '###', '##', '**', or '`').
- Use bullet points (- ) and concise paragraphs.
- Keep sections clearly separated by uppercase titles."""

DEFAULT_TIMEOUT_LOCAL = 180
DEFAULT_TIMEOUT_CLOUD = 90


def _validate_request(
    provider_name: str,
    base_url: str | None = None,
    allow_cloud: bool = False,
    timeout: int | None = None,
) -> tuple[Provider, str, str, int]:
    if provider_name not in PROVIDERS:
        raise ValueError(f"Unknown provider '{provider_name}'. Use `poirot models` to list supported providers.")
    provider = PROVIDERS[provider_name]
    endpoint = (base_url or provider.base_url or "").rstrip("/")
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    endpoint_host = urlparse(endpoint).hostname
    remote_destination = endpoint_host not in local_hosts
    if remote_destination and not allow_cloud:
        raise ValueError("Cloud explanation is disabled by default because evidence may be sensitive. Re-run with --allow-cloud after reviewing the data-sharing policy.")
    api_key = os.environ.get(provider.environment_key) if provider.environment_key else "local-no-key"
    if not api_key:
        raise ValueError(f"Set {provider.environment_key} before using {provider.name}.")
    effective_timeout = timeout or (DEFAULT_TIMEOUT_CLOUD if remote_destination else DEFAULT_TIMEOUT_LOCAL)
    return provider, endpoint, api_key, effective_timeout


def explain_stream(
    evidence: dict,
    provider_name: str,
    model: str | None = None,
    base_url: str | None = None,
    *,
    allow_cloud: bool = False,
    timeout: int | None = None,
) -> Generator[str, None, None]:
    # Stream token chunks as they arrive from the upstream LLM endpoint
    provider, endpoint, api_key, effective_timeout = _validate_request(
        provider_name, base_url, allow_cloud, timeout
    )
    try:
        import httpx
    except ImportError as exc:
        raise ValueError("Install poirot[llm] to call LLM providers.") from exc

    payload_evidence = json.dumps(evidence, ensure_ascii=False)
    model = model or provider.default_model
    user_prompt = "Explain this evidence:\n" + payload_evidence

    try:
        if provider.protocol == "anthropic":
            url = endpoint + "/messages"
            headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
            body = {
                "model": model,
                "max_tokens": 1500,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_prompt}],
                "stream": True,
            }
            with httpx.stream("POST", url, headers=headers, json=body, timeout=effective_timeout) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:].strip()
                        if not data_str or data_str == "[DONE]":
                            continue
                        try:
                            data = json.loads(data_str)
                            if data.get("type") == "content_block_delta":
                                delta = data.get("delta", {})
                                if delta.get("type") == "text_delta":
                                    yield delta.get("text", "")
                        except json.JSONDecodeError:
                            pass
        elif provider.protocol == "google":
            # Fallback to non-streaming or full request for google
            url = endpoint + f"/models/{model}:generateContent"
            response = httpx.post(
                url,
                headers={"x-goog-api-key": api_key},
                json={
                    "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                    "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                    "generationConfig": {"temperature": 0.1},
                },
                timeout=effective_timeout,
            )
            response.raise_for_status()
            yield response.json()["candidates"][0]["content"]["parts"][0]["text"]
        else:
            # OpenAI-compatible streaming
            url = endpoint + "/chat/completions"
            headers = {"Authorization": f"Bearer {api_key}"}
            body = {
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.1,
                "stream": True,
            }
            with httpx.stream("POST", url, headers=headers, json=body, timeout=effective_timeout) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:].strip()
                        if not data_str or data_str == "[DONE]":
                            continue
                        try:
                            data = json.loads(data_str)
                            choices = data.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    yield content
                        except json.JSONDecodeError:
                            pass
    except httpx.TimeoutException:
        raise ValueError(f"Request to {provider_name} timed out after {effective_timeout}s. Use --timeout to increase the limit, or try a smaller model.")
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        try:
            exc.response.read()
            err_body = exc.response.text[:300]
        except Exception:
            err_body = ""
        if status == 401:
            raise ValueError(f"Authentication failed for {provider_name}. Check {provider.environment_key or 'your API key'}.") from exc
        elif status == 402:
            raise ValueError(f"{provider_name} returned HTTP 402 (Payment Required): Insufficient credits or quota. {err_body}") from exc
        elif status == 429:
            raise ValueError(f"Rate limited by {provider_name}. Wait and retry, or use a different provider.") from exc
        else:
            raise ValueError(f"{provider_name} returned HTTP {status}: {err_body}") from exc
    except httpx.ConnectError:
        raise ValueError(f"Could not connect to {provider_name} at {endpoint}. Is the server running?")


def explain(
    evidence: dict,
    provider_name: str,
    model: str | None = None,
    base_url: str | None = None,
    *,
    allow_cloud: bool = False,
    timeout: int | None = None,
) -> dict:
    model_name = model or PROVIDERS.get(provider_name, Provider(provider_name, "unknown", None, None, "")).default_model
    chunks = list(explain_stream(evidence, provider_name, model, base_url, allow_cloud=allow_cloud, timeout=timeout))
    content = "".join(chunks)
    return {"kind": "llm_interpretation", "provider": provider_name, "model": model_name, "input_policy": "structured evidence only; no raw binary bytes", "explanation": content}
