# Architecture

## MVP pipeline

```
binary files → parser → normalized analysis facts → deterministic diff/ranking
                                                      ↓
                                             JSON evidence bundle
                                                      ↓
                                         optional LLM explanation
```

`analysis` owns all facts. The LLM layer has no binary-file access and receives neither raw bytes nor disassembly by default.

## Parser strategy

The built-in parser identifies ELF, Mach-O (thin and FAT), and PE and safely extracts strings. It derives Mach-O architecture from the target header, so analysis is not tied to the host OS. An IPSW adapter inventories ZIP members and manifests using only the Python standard library. LIEF is an optional adapter for normalized sections, imports, exports, symbols, and named-function candidates. Later adapters can use rizin/Ghidra for CFG recovery while preserving the same models.

## Matching and ranking

The first matcher pairs functions by exact symbol name. A function present only in the new binary is added; one only in the old is removed. Matched functions compare size and collected call references. The ranking formula is configured in code and returns evidence alongside its score.

## LLM providers

The provider registry covers OpenAI, Anthropic, Google Gemini, DeepSeek, Groq, OpenRouter, and local OpenAI-compatible servers. “Top models” change rapidly, so the CLI exposes provider defaults as editable presets rather than hard-coding a permanent universal model list. Ollama, LM Studio, and llama.cpp use the same local-compatible adapter. Anthropic and Gemini use their native REST formats; the remaining cloud/local adapters use the broadly supported OpenAI-compatible chat format.

## Local model recommendation

`recommend` profiles CPU architecture, RAM, and—in macOS environments—Metal/GPU memory heuristics. Poirot has one fixed LLM task: explain structured binary-diff evidence. It compares curated code-focused, general-instruction, and reasoning-distilled candidates, then selects the highest task-scoring model that fits a conservative sustained-use memory budget. It never downloads or starts models; the user remains in control.

For binary-change explanations, a code-oriented 7B–14B instruct model is normally the best quality/latency tradeoff. Larger 32B+ models are suggested only when memory permits and the task needs deeper synthesis.
