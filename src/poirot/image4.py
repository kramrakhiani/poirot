"""Apple Image4 (IMG4 / IM4P) container parser and LZFSE/LZSS decompressor.

Unwraps Apple IM4P payloads (e.g. kernelcache, SEP, iBoot, AOP) to expose the
underlying Mach-O binary for static analysis.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any


def is_image4(data: bytes) -> bool:
    """Return True if data starts with ASN.1 sequence containing IM4P or IMG4."""
    if len(data) < 16:
        return False
    # Check for IM4P or IMG4 ASCII signatures near the beginning
    return b"IM4P" in data[:64] or b"IMG4" in data[:64] or data.startswith(b"bvx2") or data.startswith(b"bvxn") or data.startswith(b"complzss")


def parse_image4_payload(data: bytes) -> tuple[dict[str, Any], bytes]:
    """Parse IM4P container metadata and extract/decompress the inner payload.

    Returns (metadata_dict, decompressed_bytes).
    """
    metadata: dict[str, Any] = {
        "is_image4": True,
        "tag": None,
        "description": None,
        "compression": None,
    }

    # Extract tag (e.g. 'krnl', 'sep', 'ibot') if present
    im4p_pos = data.find(b"IM4P")
    if im4p_pos != -1 and im4p_pos + 12 <= len(data):
        # In ASN.1 DER: 16 04 <TAG: 4 bytes>
        tag_pos = im4p_pos + 4
        if data[tag_pos:tag_pos + 2] == b"\x16\x04":
            metadata["tag"] = data[tag_pos + 2:tag_pos + 6].decode("ascii", errors="replace")
        elif data[tag_pos + 1:tag_pos + 3] == b"\x16\x04":
            metadata["tag"] = data[tag_pos + 3:tag_pos + 7].decode("ascii", errors="replace")

    # Extract description string if present
    desc_pos = data.find(b"\x16", (im4p_pos + 8) if im4p_pos != -1 else 0)
    if desc_pos != -1 and desc_pos + 2 <= len(data):
        desc_len = data[desc_pos + 1]
        if desc_pos + 2 + desc_len <= len(data) and 0 < desc_len < 128:
            desc_candidate = data[desc_pos + 2:desc_pos + 2 + desc_len].decode("utf-8", errors="replace")
            if any(c.isalnum() for c in desc_candidate):
                metadata["description"] = desc_candidate

    # Search for LZFSE magic (bvx2, bvxn, bvx1)
    lzfse_pos = -1
    for magic in (b"bvx2", b"bvxn", b"bvx1"):
        pos = data.find(magic)
        if pos != -1:
            lzfse_pos = pos
            break

    if lzfse_pos != -1:
        metadata["compression"] = "LZFSE"
        try:
            import lzfse
            decompressed = lzfse.decompress(data[lzfse_pos:])
            if decompressed:
                return metadata, decompressed
        except Exception as exc:
            metadata["decompress_error"] = str(exc)

    # Search for LZSS magic (complzss)
    lzss_pos = data.find(b"complzss")
    if lzss_pos != -1:
        metadata["compression"] = "LZSS"

    # Search for raw Mach-O header inside the container
    for macho_magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"):
        macho_pos = data.find(macho_magic)
        if macho_pos != -1:
            return metadata, data[macho_pos:]

    return metadata, data
