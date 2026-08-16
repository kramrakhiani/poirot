from __future__ import annotations

import os
import re
import struct
import zipfile
import plistlib
from pathlib import Path

from .models import BinaryAnalysis, Function
from .security import derive_security_signals

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
MACHO_CPU_TYPES = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64"}
MAX_STRING_RESULTS = 250
STRING_CHUNK_SIZE = 1024 * 1024
MAX_IPSW_MANIFEST_BYTES = 16 * 1024 * 1024


def extract_strings(path: Path, limit: int = MAX_STRING_RESULTS) -> list[str]:
    results: list[str] = []
    carry = b""
    with path.open("rb") as binary:
        while True:
            chunk = binary.read(STRING_CHUNK_SIZE)
            if not chunk:
                break
            data = carry + chunk
            for match in PRINTABLE.finditer(data):
                if match.end() <= len(carry):
                    continue
                if match.end() == len(data):
                    # Preserve a possible chunk-spanning string until its end is known.
                    break
                results.append(match.group().decode("utf-8", errors="replace"))
                if len(results) == limit:
                    return results
            tail = PRINTABLE.search(data[max(0, len(data) - 4096):])
            carry = tail.group()[-4096:] if tail and tail.end() == len(data[max(0, len(data) - 4096):]) else b""
    if carry and len(results) < limit:
        results.append(carry.decode("utf-8", errors="replace"))
    return results


def _header(data: bytes) -> tuple[str, str | None, int | None]:
    if data.startswith(b"\x7fELF"):
        # EI_CLASS/EI_DATA define the width and byte order of the fixed ELF header.
        bits = 64 if len(data) > 4 and data[4] == 2 else 32
        endian = "<" if len(data) > 5 and data[5] == 1 else ">"
        machine = struct.unpack_from(endian + "H", data, 18)[0] if len(data) >= 20 else 0
        arch = {3: "x86", 62: "x86_64", 183: "aarch64", 40: "arm"}.get(machine, f"ELF machine {machine}")
        entry_offset = 24 if bits == 64 else 24
        entry_fmt = endian + ("Q" if bits == 64 else "I")
        entry = struct.unpack_from(entry_fmt, data, entry_offset)[0] if len(data) >= entry_offset + bits // 8 else None
        return "ELF", arch, entry
    if data[:2] == b"MZ" and len(data) >= 64:
        # DOS e_lfanew points to the PE signature and COFF header.
        pe_offset = struct.unpack_from("<I", data, 60)[0]
        # The entry RVA lives 40 bytes past the PE signature.
        if pe_offset + 44 <= len(data) and data[pe_offset:pe_offset + 4] == b"PE\0\0":
            machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
            optional_offset = pe_offset + 24
            optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
            entry_rva = struct.unpack_from("<I", data, optional_offset + 16)[0]
            architecture = {0x14C: "x86", 0x8664: "x86_64", 0x1C0: "arm", 0xAA64: "arm64"}.get(machine, f"PE machine {machine:#x}")
            return f"PE {64 if optional_magic == 0x20B else 32}-bit", architecture, entry_rva
        return "PE (truncated or malformed)", None, None
    magic = data[:4]
    thin = {b"\xfe\xed\xfa\xce": (">", "Mach-O 32-bit"), b"\xce\xfa\xed\xfe": ("<", "Mach-O 32-bit"), b"\xfe\xed\xfa\xcf": (">", "Mach-O 64-bit"), b"\xcf\xfa\xed\xfe": ("<", "Mach-O 64-bit")}
    if magic in thin and len(data) >= 12:
        endian, label = thin[magic]
        cputype = struct.unpack_from(endian + "I", data, 4)[0]
        return label, MACHO_CPU_TYPES.get(cputype, f"Mach-O CPU {cputype:#x}"), None
    fat_endian = {b"\xca\xfe\xba\xbe": ">", b"\xbe\xba\xfe\xca": "<"}.get(magic)
    if fat_endian and len(data) >= 8:
        count = min(struct.unpack_from(fat_endian + "I", data, 4)[0], 16)
        architectures = []
        for index in range(count):
            offset = 8 + index * 20
            if offset + 4 <= len(data):
                architectures.append(MACHO_CPU_TYPES.get(struct.unpack_from(fat_endian + "I", data, offset)[0], "unknown"))
        return "Mach-O universal (FAT)", ", ".join(dict.fromkeys(architectures)) or "unknown", None
    return "Unknown", None, None


def _lief_analysis(path: Path, base: BinaryAnalysis) -> BinaryAnalysis:
    try:
        import lief  # type: ignore
        if hasattr(lief, "logging") and hasattr(lief.logging, "disable"):
            lief.logging.disable()
    except ImportError:
        base.parser_notes.append("Install poirot[analysis] for imports, symbols, and function candidates.")
        return base
    try:
        # LIEF is optional and processes attacker-controlled binary input.
        parsed = lief.parse(str(path))
        if parsed is None:
            return base
        # If LIEF returns a FatBinary container, inspect the primary slice
        if hasattr(parsed, "at") and hasattr(parsed, "size") and parsed.size > 0:
            binary = parsed.at(0)
        elif isinstance(parsed, (list, tuple)) and parsed:
            binary = parsed[0]
        else:
            binary = parsed

        base.entry_point = int(binary.entrypoint) if getattr(binary, "entrypoint", 0) else base.entry_point
        base.executable_sections = [str(section.name) for section in binary.sections if _is_executable_section(section)]
        base.imports = _named_items(getattr(binary, "imported_functions", []))
        base.exports = _named_items(getattr(binary, "exported_functions", []))
        base.functions = _function_candidates(binary)
        base.parser_notes.append("Rich structural data extracted using LIEF.")
    except Exception as exc:
        base.parser_notes.append(f"LIEF could not parse this binary: {exc}")
    return base


def _named_items(items: object) -> list[str]:
    names = {str(getattr(item, "name", item)).strip() for item in items}  # type: ignore[union-attr]
    return sorted(name for name in names if name)


from .demangle import demangle_symbol
from .entitlements import extract_entitlements_from_file


def _function_candidates(binary: object) -> list[Function]:
    # Prefer backend-recovered functions. Arbitrary symbols include data objects.
    candidates = list(getattr(binary, "functions", []))
    if not candidates:
        candidates = [
            symbol
            for symbol in getattr(binary, "symbols", [])
            if "FUNC" in str(getattr(symbol, "type", "")).upper()
        ]
    functions = []
    for candidate in candidates:
        name = str(getattr(candidate, "name", "")).strip()
        address = int(getattr(candidate, "address", getattr(candidate, "value", 0)) or 0)
        size = int(getattr(candidate, "size", 0) or 0)
        if name and (address or size):
            demangled = demangle_symbol(name)
            functions.append(Function(
                name=name,
                demangled_name=demangled if demangled != name else None,
                address=address or None,
                size=size or None,
            ))
    return functions


def _is_executable_section(section: object) -> bool:
    name = str(getattr(section, "name", "")).casefold()
    characteristics = int(getattr(section, "characteristics", 0))
    return bool(characteristics & 0x20000000) or name in {".text", "__text", "__stubs", ".plt"}


def extract_mach_o_fileset_entries(raw_bytes: bytes) -> list[dict[str, Any]]:
    # Extract LC_FILESET_ENTRY (0x80000035) load commands from Mach-O 64-bit MH_FILESET container
    import hashlib
    if len(raw_bytes) < 32:
        return []
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from("<7I", raw_bytes, 0)
    if magic not in (0xfeedfacf, 0xfeedface):
        return []
    is_64 = magic == 0xfeedfacf
    hdr_size = 32 if is_64 else 28
    entries = []
    offset = hdr_size
    for _ in range(ncmds):
        if offset + 8 > len(raw_bytes):
            break
        cmd, cmdsize = struct.unpack_from("<2I", raw_bytes, offset)
        if cmd == 0x80000035:  # LC_FILESET_ENTRY
            va, foff, id_off, reserved = struct.unpack_from("<QQII", raw_bytes, offset + 8)
            str_bytes = raw_bytes[offset + id_off:offset + cmdsize].split(b"\x00", 1)[0]
            entry_id = str_bytes.decode("utf-8", errors="replace")
            entries.append({"name": entry_id, "file_offset": foff, "virtual_address": va})
        offset += cmdsize

    results = []
    for i, e in enumerate(entries):
        start = e["file_offset"]
        end = entries[i + 1]["file_offset"] if i + 1 < len(entries) else len(raw_bytes)
        size = max(0, end - start)
        chunk = raw_bytes[start:start + size]
        h = hashlib.sha256(chunk).hexdigest() if chunk else ""
        results.append({
            "name": e["name"],
            "file_offset": e["file_offset"],
            "virtual_address": e["virtual_address"],
            "size_bytes": size,
            "sha256": h,
        })
    return results


from .image4 import is_image4, parse_image4_payload


def analyze_binary(path_value: str) -> BinaryAnalysis:
    import tempfile

    path = Path(path_value)
    if not path.is_file():
        raise ValueError(f"Input is not a regular file: {path}")

    with path.open("rb") as binary:
        header = binary.read(4096)

    # Automatic Apple Image4 (IM4P/IMG4/LZFSE) container handling
    if is_image4(header):
        with path.open("rb") as f:
            raw_data = f.read(128 * 1024 * 1024)
        im4p_meta, decompressed_data = parse_image4_payload(raw_data)
        with tempfile.NamedTemporaryFile(prefix="poirot_im4p_", delete=False) as tmp:
            tmp.write(decompressed_data)
            tmp_path = Path(tmp.name)

        try:
            fmt, arch, entry = _header(decompressed_data[:4096])
            tag_info = f" (Image4 tag: {im4p_meta['tag']})" if im4p_meta.get("tag") else " (Image4 Container)"
            full_fmt = f"{fmt}{tag_info}" if fmt != "Unknown" else f"Apple Image4 Payload ({im4p_meta.get('tag') or 'raw'})"

            result = BinaryAnalysis(
                path=str(path),
                format=full_fmt,
                architecture=arch,
                entry_point=entry,
                strings=extract_strings(tmp_path),
            )
            result.parser_notes.append(f"Unwrapped Apple Image4 payload (tag: {im4p_meta.get('tag') or '?'}, compression: {im4p_meta.get('compression') or 'none'}, decompressed: {len(decompressed_data):,} bytes).")
            result.fileset_entries = extract_mach_o_fileset_entries(decompressed_data)
            if result.fileset_entries:
                result.parser_notes.append(f"Parsed {len(result.fileset_entries)} Mach-O fileset entries (kernel extensions & core modules).")
            result = _lief_analysis(tmp_path, result)
            result.entitlements = extract_entitlements_from_file(tmp_path)
            if result.entitlements:
                result.parser_notes.append(f"Extracted {len(result.entitlements)} embedded entitlement keys.")
            result.security_signals = derive_security_signals(result.strings, result.imports, result.exports, [function.name for function in result.functions])
            return result
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass

    fmt, arch, entry = _header(header)
    result = BinaryAnalysis(path=str(path), format=fmt, architecture=arch, entry_point=entry, strings=extract_strings(path))
    result.parser_notes.append(f"Read {os.path.getsize(path):,} bytes in bounded chunks; input was never executed.")
    with path.open("rb") as f:
        file_bytes = f.read(128 * 1024 * 1024)
    result.fileset_entries = extract_mach_o_fileset_entries(file_bytes)
    if result.fileset_entries:
        result.parser_notes.append(f"Parsed {len(result.fileset_entries)} Mach-O fileset entries (kernel extensions & core modules).")
    result = _lief_analysis(path, result)
    result.entitlements = extract_entitlements_from_file(path)
    if result.entitlements:
        result.parser_notes.append(f"Extracted {len(result.entitlements)} embedded entitlement keys.")
    result.security_signals = derive_security_signals(result.strings, result.imports, result.exports, [function.name for function in result.functions])
    return result


def _build_manifest_summary(archive: zipfile.ZipFile, manifest_name: str) -> dict:
    info = archive.getinfo(manifest_name)
    if info.file_size > MAX_IPSW_MANIFEST_BYTES:
        return {"error": f"{manifest_name} exceeds the {MAX_IPSW_MANIFEST_BYTES // 1024 // 1024} MiB manifest limit."}
    try:
        manifest = plistlib.loads(archive.read(manifest_name))
    except (OSError, plistlib.InvalidFileException, ValueError, RuntimeError) as error:
        # RuntimeError covers encrypted ZIP entries that Python cannot decompress.
        return {"error": f"Could not parse {manifest_name}: {error}"}
    identities = []
    for identity in manifest.get("BuildIdentities", [])[:50]:
        identity_info = identity.get("Info", {})
        components = identity.get("Manifest", {})
        paths = sorted(
            component.get("Info", {}).get("Path")
            for component in components.values()
            if isinstance(component, dict) and component.get("Info", {}).get("Path")
        )
        identities.append({
            "device_class": identity_info.get("DeviceClass"),
            "build_number": identity_info.get("BuildNumber"),
            "variant": identity_info.get("Variant"),
            "component_paths": paths[:500],
        })
    return {
        "product_version": manifest.get("ProductVersion"),
        "product_build_version": manifest.get("ProductBuildVersion"),
        "supported_product_types": manifest.get("SupportedProductTypes", []),
        "build_identities": identities,
    }


def inspect_ipsw(path_value: str, limit: int = 500) -> dict:
    path = Path(path_value)
    if not zipfile.is_zipfile(path):
        raise ValueError("An IPSW must be a ZIP-compatible archive.")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > 100_000:
            raise ValueError("Archive has over 100,000 members; refusing an unbounded inventory.")

        categorized: dict[str, list[dict]] = {
            "kernel": [],
            "secure_enclave": [],
            "system_images": [],
            "trust_cache": [],
            "bootloaders": [],
            "baseband": [],
            "device_tree": [],
            "accessory_firmware": [],
            "manifests": [],
            "other": [],
        }

        for m in members:
            fn = m.filename
            fn_lower = fn.lower()
            size = m.file_size
            entry = {"filename": fn, "size_bytes": size}

            if fn.endswith("/"):
                continue

            if "kernelcache" in fn_lower:
                categorized["kernel"].append(entry)
            elif "sep" in fn_lower or "secureenclave" in fn_lower:
                categorized["secure_enclave"].append(entry)
            elif fn_lower.endswith(".dmg"):
                categorized["system_images"].append(entry)
            elif "trustcache" in fn_lower:
                categorized["trust_cache"].append(entry)
            elif any(b in fn_lower for b in ("iboot", "llb", "ibss", "ibec", "aop")):
                categorized["bootloaders"].append(entry)
            elif any(b in fn_lower for b in (".bbfw", ".fls", "baseband")):
                categorized["baseband"].append(entry)
            elif "devicetree" in fn_lower:
                categorized["device_tree"].append(entry)
            elif any(b in fn_lower for b in ("ftab.bin", "multitouch", "haptics", "applelpm", "usbcfw", "uarp")):
                categorized["accessory_firmware"].append(entry)
            elif fn.rsplit("/", 1)[-1] in {"BuildManifest.plist", "Restore.plist", "Info.plist"}:
                categorized["manifests"].append(entry)
            else:
                categorized["other"].append(entry)

        # Sort within each category by size descending
        for cat_list in categorized.values():
            cat_list.sort(key=lambda x: x["size_bytes"], reverse=True)

        build_manifest = next((m["filename"] for m in categorized["manifests"] if m["filename"].endswith("BuildManifest.plist")), None)

        manifest_candidates = [m["filename"] for m in categorized["manifests"]]
        mach_o_candidates = [m["filename"] for m in (categorized["kernel"] + categorized["secure_enclave"] + categorized["bootloaders"] + categorized["accessory_firmware"])]

        return {
            "kind": "ipsw_inventory",
            "path": str(path),
            "archive_format": "ZIP/IPSW",
            "member_count": len(members),
            "uncompressed_size_bytes": sum(m.file_size for m in members),
            "build_manifest": _build_manifest_summary(archive, build_manifest) if build_manifest else None,
            "manifest_candidates": manifest_candidates,
            "mach_o_candidates": mach_o_candidates[:limit],
            "subsystems": categorized,
            "notes": [
                "Archive inspected in bounded memory; nothing was extracted to disk.",
                "Subsystems categorized into Kernel, SEP, Cryptex/DMGs, TrustCaches, Baseband, and Bootloaders.",
                "Use `poirot ipsw-extract <archive> <path> <out>` to extract any specific payload for deep analysis.",
            ],
        }


def extract_ipsw_component(archive_path: str, member_name: str, output_path: str) -> Path:
    source = Path(archive_path)
    destination = Path(output_path).resolve()
    # Guard against Zip Slip: the resolved output must not escape its parent.
    parent = destination.parent.resolve()
    if not str(destination).startswith(str(parent)):
        raise ValueError(f"Path traversal detected in output path: {output_path}")
    if destination.exists() and destination.is_dir():
        raise ValueError(f"Output path is a directory: {destination}")
    # Reject archive member names containing traversal sequences.
    if ".." in member_name.split("/"):
        raise ValueError(f"Path traversal detected in archive member: {member_name}")
    with zipfile.ZipFile(source) as archive:
        try:
            member = archive.getinfo(member_name)
        except KeyError as error:
            raise ValueError(f"IPSW component not found: {member_name}") from error
        if member.is_dir():
            raise ValueError(f"IPSW component is a directory: {member_name}")
        with archive.open(member) as component, destination.open("wb") as output:
            while chunk := component.read(STRING_CHUNK_SIZE):
                output.write(chunk)
    return destination
