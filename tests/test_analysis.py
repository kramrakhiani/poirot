import zipfile

from poirot.analysis import _header, extract_strings, extract_ipsw_component, inspect_ipsw


def test_pe_header_reports_target_architecture():
    header = bytearray(512)
    header[:2] = b"MZ"
    header[60:64] = (128).to_bytes(4, "little")
    header[128:132] = b"PE\0\0"
    header[132:134] = (0xAA64).to_bytes(2, "little")
    header[152:154] = (0x20B).to_bytes(2, "little")
    header[168:172] = (0x1234).to_bytes(4, "little")
    assert _header(bytes(header)) == ("PE 64-bit", "arm64", 0x1234)


def test_truncated_pe_is_not_reported_as_valid():
    assert _header(b"MZ" + b"\0" * 62)[0] == "PE (truncated or malformed)"


def test_macho_architecture_comes_from_target_header():
    header = b"\xcf\xfa\xed\xfe" + (0x0100000C).to_bytes(4, "little") + b"\x00" * 8
    assert _header(header)[1] == "arm64"


def test_ipsw_inventory_uses_standard_zip(tmp_path):
    ipsw = tmp_path / "sample.ipsw"
    with zipfile.ZipFile(ipsw, "w") as archive:
        archive.writestr("BuildManifest.plist", "manifest")
        archive.writestr("Firmware/usr/lib/test.dylib", "binary")
    inventory = inspect_ipsw(str(ipsw))
    assert inventory["member_count"] == 2
    assert inventory["manifest_candidates"] == ["BuildManifest.plist"]


def test_streamed_string_extraction_handles_chunk_boundary(tmp_path, monkeypatch):
    binary = tmp_path / "fixture.bin"
    binary.write_bytes(b"A" * 10 + b"boundary-string" + b"\x00")
    monkeypatch.setattr("poirot.analysis.STRING_CHUNK_SIZE", 16)
    assert extract_strings(binary) == ["AAAAAAAAAAboundary-string"]


def test_ipsw_extract_rejects_path_traversal_in_member(tmp_path):
    ipsw = tmp_path / "evil.ipsw"
    with zipfile.ZipFile(ipsw, "w") as archive:
        archive.writestr("../../etc/passwd", "root")
    import pytest
    with pytest.raises(ValueError, match="Path traversal"):
        extract_ipsw_component(str(ipsw), "../../etc/passwd", str(tmp_path / "out"))


def test_ipsw_extract_writes_component(tmp_path):
    ipsw = tmp_path / "sample.ipsw"
    with zipfile.ZipFile(ipsw, "w") as archive:
        archive.writestr("Firmware/kernel", b"KERNELDATA")
    out = tmp_path / "kernel_out"
    result = extract_ipsw_component(str(ipsw), "Firmware/kernel", str(out))
    assert result.exists()
    assert result.read_text() == "KERNELDATA"
