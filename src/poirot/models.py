from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Function:
    name: str
    demangled_name: str | None = None
    address: int | None = None
    size: int | None = None
    calls: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SecuritySignal:
    category: str
    evidence: list[str]
    rationale: str


@dataclass
class BinaryAnalysis:
    path: str
    format: str
    architecture: str | None
    entry_point: int | None
    executable_sections: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    security_signals: list[SecuritySignal] = field(default_factory=list)
    entitlements: dict[str, Any] = field(default_factory=dict)
    fileset_entries: list[dict[str, Any]] = field(default_factory=list)
    parser_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
