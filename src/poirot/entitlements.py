"""Mach-O embedded entitlements extraction and differential analysis.

Parses XML/plist entitlements from __TEXT,__entitlements sections or
LC_CODE_SIGNATURE embedded SuperBlobs (magic 0xfade7171).
"""
from __future__ import annotations

import plistlib
import re
import struct
from pathlib import Path
from typing import Any

CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_SUPERBLOB = 0xFADE0CC0


def _parse_xml_plist(data: bytes) -> dict[str, Any]:
    """Extract and parse plist XML if found within bytes."""
    # Find XML plist boundaries
    start = data.find(b"<?xml")
    if start == -1:
        start = data.find(b"<plist")
    if start == -1:
        return {}

    end = data.find(b"</plist>")
    if end == -1:
        return {}
    end += len(b"</plist>")

    try:
        parsed = plistlib.loads(data[start:end])
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _extract_from_superblob(data: bytes) -> dict[str, Any]:
    """Scan for Code Signing SuperBlob and extract embedded entitlements blob."""
    # Search for SuperBlob magic (0xfade0cc0 in big endian)
    offset = 0
    while True:
        pos = data.find(b"\xfa\xde\x0c\xc0", offset)
        if pos == -1 or pos + 12 > len(data):
            break
        try:
            length, count = struct.unpack_from(">II", data, pos + 4)
            if 0 < length <= len(data) - pos and count < 100:
                for i in range(count):
                    index_offset = pos + 12 + (i * 8)
                    if index_offset + 8 <= len(data):
                        blob_type, blob_offset = struct.unpack_from(">II", data, index_offset)
                        if blob_type == 5 or blob_type == 7:  # CSSLOT_ENTITLEMENTS
                            target_offset = pos + blob_offset
                            if target_offset + 8 <= len(data):
                                magic, blob_len = struct.unpack_from(">II", data, target_offset)
                                if magic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
                                    xml_data = data[target_offset + 8:target_offset + blob_len]
                                    parsed = _parse_xml_plist(xml_data)
                                    if parsed:
                                        return parsed
        except Exception:
            pass
        offset = pos + 4
    return {}


def extract_entitlements_from_file(path: Path) -> dict[str, Any]:
    """Extract embedded entitlements from a Mach-O or iOS binary."""
    try:
        # Read up to 8MB or file size to bound memory consumption
        with path.open("rb") as f:
            data = f.read(8 * 1024 * 1024)
        # 1. Try SuperBlob parsing
        ent = _extract_from_superblob(data)
        if ent:
            return ent
        # 2. Try XML plist scanner
        return _parse_xml_plist(data)
    except Exception:
        return {}


def diff_entitlements(old_ent: dict[str, Any], new_ent: dict[str, Any]) -> dict[str, Any]:
    """Compare two sets of entitlements and highlight additions/changes."""
    old_keys = set(old_ent.keys())
    new_keys = set(new_ent.keys())

    added = {k: new_ent[k] for k in sorted(new_keys - old_keys)}
    removed = {k: old_ent[k] for k in sorted(old_keys - new_keys)}
    modified = {}

    for k in sorted(old_keys & new_keys):
        if old_ent[k] != new_ent[k]:
            modified[k] = {"before": old_ent[k], "after": new_ent[k]}

    # Privilege escalation / attack surface risk signals
    security_alerts = []
    for k in added:
        if "private" in k.lower():
            security_alerts.append(f"Private entitlement added: {k}")
        elif "sandbox" in k.lower():
            security_alerts.append(f"Sandbox entitlement modified: {k}")
        elif "tcc" in k.lower() or "accessibility" in k.lower():
            security_alerts.append(f"Privacy/TCC entitlement added: {k}")

    return {
        "added": added,
        "removed": removed,
        "modified": modified,
        "security_alerts": security_alerts,
        "has_changes": bool(added or removed or modified),
    }
