"""IPSW firmware archive differential analysis.

Compares two Apple IPSW archives at the manifest, build identity, and
component payload levels without requiring multi-gigabyte extraction.
"""
from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path
from typing import Any

from .analysis import MAX_IPSW_MANIFEST_BYTES


def is_ipsw_file(path_value: str) -> bool:
    """Return True if the file looks like an IPSW (ZIP with BuildManifest or .ipsw extension)."""
    p = Path(path_value)
    if not p.is_file():
        return False
    if p.suffix.casefold() == ".ipsw":
        return True
    # If not named .ipsw, check if it's a zip containing BuildManifest.plist
    if zipfile.is_zipfile(p):
        try:
            with zipfile.ZipFile(p) as z:
                names = z.namelist()[:1000]
                return any(n.endswith("BuildManifest.plist") for n in names)
        except Exception:
            return False
    return False


def _categorize_member(filename: str) -> str:
    """Classify an IPSW member path into an iOS security subsystem."""
    fn = filename.lower()
    if "kernelcache" in fn:
        return "kernel"
    if "sep" in fn or "secureenclave" in fn:
        return "secure_enclave"
    if any(b in fn for b in ("iboot", "llb", "ibss", "ibec", "aop")):
        return "bootloaders"
    if any(b in fn for b in (".bbfw", ".fls", "baseband")):
        return "baseband"
    if "cryptex" in fn:
        return "cryptex"
    if fn.endswith(".dmg"):
        return "system_images"
    if "trustcache" in fn:
        return "trustcache"
    if "devicetree" in fn:
        return "devicetree"
    if fn.endswith(".plist"):
        return "manifests"
    return "other_firmware"


def _read_manifest(archive: zipfile.ZipFile, manifest_name: str) -> dict[str, Any]:
    try:
        info = archive.getinfo(manifest_name)
        if info.file_size > MAX_IPSW_MANIFEST_BYTES:
            return {}
        return plistlib.loads(archive.read(manifest_name))
    except Exception:
        return {}


def diff_ipsw(old_path_value: str, new_path_value: str) -> dict[str, Any]:
    """Compare two IPSW firmware archives deterministically."""
    old_path = Path(old_path_value)
    new_path = Path(new_path_value)

    if not zipfile.is_zipfile(old_path):
        raise ValueError(f"Old file is not a valid ZIP/IPSW archive: {old_path}")
    if not zipfile.is_zipfile(new_path):
        raise ValueError(f"New file is not a valid ZIP/IPSW archive: {new_path}")

    with zipfile.ZipFile(old_path) as old_z, zipfile.ZipFile(new_path) as new_z:
        old_members = {m.filename: m for m in old_z.infolist()}
        new_members = {m.filename: m for m in new_z.infolist()}

        # 1. Manifest / Build Comparison
        old_bm_name = next((n for n in old_members if n.endswith("BuildManifest.plist")), None)
        new_bm_name = next((n for n in new_members if n.endswith("BuildManifest.plist")), None)

        old_bm = _read_manifest(old_z, old_bm_name) if old_bm_name else {}
        new_bm = _read_manifest(new_z, new_bm_name) if new_bm_name else {}

        old_ver = old_bm.get("ProductVersion")
        new_ver = new_bm.get("ProductVersion")
        old_build = old_bm.get("ProductBuildVersion")
        new_build = new_bm.get("ProductBuildVersion")

        old_devices = set(old_bm.get("SupportedProductTypes", []))
        new_devices = set(new_bm.get("SupportedProductTypes", []))

        build_changes = {
            "old_product_version": old_ver,
            "new_product_version": new_ver,
            "old_build_number": old_build,
            "new_build_number": new_build,
            "version_changed": old_ver != new_ver or old_build != new_build,
            "supported_devices_added": sorted(new_devices - old_devices),
            "supported_devices_removed": sorted(old_devices - new_devices),
            "supported_devices_common": sorted(old_devices & new_devices),
        }

        # 2. Archive Component Diffing
        old_names = set(old_members)
        new_names = set(new_members)

        added_names = sorted(new_names - old_names)
        removed_names = sorted(old_names - new_names)
        common_names = sorted(old_names & new_names)

        modified = []
        unchanged_count = 0

        for name in common_names:
            om = old_members[name]
            nm = new_members[name]
            # Compare CRC32 and uncompressed file size
            if om.CRC != nm.CRC or om.file_size != nm.file_size:
                size_delta = nm.file_size - om.file_size
                category = _categorize_member(name)
                modified.append({
                    "filename": name,
                    "category": category,
                    "old_size_bytes": om.file_size,
                    "new_size_bytes": nm.file_size,
                    "size_delta_bytes": size_delta,
                    "old_crc": f"{om.CRC:#010x}",
                    "new_crc": f"{nm.CRC:#010x}",
                })
            else:
                unchanged_count += 1

        # Sort modified by magnitude of change / category relevance
        cat_priority = {
            "kernel": 1,
            "secure_enclave": 2,
            "cryptex": 3,
            "system_images": 4,
            "trustcache": 5,
            "bootloaders": 6,
            "baseband": 7,
            "devicetree": 8,
            "manifests": 9,
            "other_firmware": 10,
        }
        modified.sort(key=lambda item: (cat_priority.get(item["category"], 99), -abs(item["size_delta_bytes"])))

        # Categorized changes
        categorized_modified: dict[str, list[dict]] = {}
        for item in modified:
            categorized_modified.setdefault(item["category"], []).append(item)

        categorized_added: dict[str, list[str]] = {}
        for name in added_names:
            categorized_added.setdefault(_categorize_member(name), []).append(name)

        categorized_removed: dict[str, list[str]] = {}
        for name in removed_names:
            categorized_removed.setdefault(_categorize_member(name), []).append(name)

    return {
        "kind": "ipsw_diff",
        "old_archive": {
            "path": str(old_path),
            "product_version": old_ver,
            "build_number": old_build,
            "total_members": len(old_members),
        },
        "new_archive": {
            "path": str(new_path),
            "product_version": new_ver,
            "build_number": new_build,
            "total_members": len(new_members),
        },
        "build_changes": build_changes,
        "component_changes": {
            "total_added": len(added_names),
            "total_removed": len(removed_names),
            "total_modified": len(modified),
            "total_unchanged": unchanged_count,
            "added_by_category": categorized_added,
            "removed_by_category": categorized_removed,
            "modified_by_category": categorized_modified,
            "modified_components": modified,
        },
        "security_hotspots": [
            cat for cat in ("kernel", "secure_enclave", "cryptex", "trustcache", "bootloaders", "baseband")
            if cat in categorized_modified or cat in categorized_added
        ],
    }


def llm_ipsw_evidence(report: dict[str, Any]) -> dict[str, Any]:
    """Create a compact, privacy-safe evidence bundle for LLM interpretation of an IPSW firmware diff."""
    build = report["build_changes"]
    comp = report["component_changes"]

    # Focus on security-relevant modified components
    hotspot_details = []
    for item in comp.get("modified_components", [])[:30]:
        hotspot_details.append({
            "component": item["filename"],
            "subsystem": item["category"],
            "size_delta_bytes": item["size_delta_bytes"],
        })

    return {
        "evidence_type": "ipsw_firmware_diff",
        "evidence_version": 1,
        "firmware_transition": {
            "from_version": build.get("old_product_version") or "unknown",
            "from_build": build.get("old_build_number") or "unknown",
            "to_version": build.get("new_product_version") or "unknown",
            "to_build": build.get("new_build_number") or "unknown",
        },
        "device_support_changes": {
            "added_devices": build.get("supported_devices_added", []),
            "removed_devices": build.get("supported_devices_removed", []),
        },
        "subsystems_modified": report.get("security_hotspots", []),
        "key_component_changes": hotspot_details,
        "summary_counts": {
            "components_added": comp["total_added"],
            "components_removed": comp["total_removed"],
            "components_modified": comp["total_modified"],
            "components_unchanged": comp["total_unchanged"],
        },
        "added_subsystems": list(comp.get("added_by_category", {}).keys()),
        "removed_subsystems": list(comp.get("removed_by_category", {}).keys()),
    }
