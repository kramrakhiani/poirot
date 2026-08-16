import io
import plistlib
import zipfile
from unittest.mock import patch

from poirot.display import display_ipsw_diff
from poirot.ipsw_diff import diff_ipsw, is_ipsw_file, llm_ipsw_evidence


def _create_dummy_ipsw(path, product_version, build_number, components):
    manifest = {
        "ProductVersion": product_version,
        "ProductBuildVersion": build_number,
        "SupportedProductTypes": ["iPhone16,1"],
        "BuildIdentities": [],
    }
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("BuildManifest.plist", plistlib.dumps(manifest))
        for filename, content in components.items():
            z.writestr(filename, content)


def test_is_ipsw_file(tmp_path):
    ipsw_path = tmp_path / "test.ipsw"
    _create_dummy_ipsw(ipsw_path, "18.0", "22A100", {})
    assert is_ipsw_file(str(ipsw_path)) is True

    bin_path = tmp_path / "test.bin"
    bin_path.write_bytes(b"not an ipsw")
    assert is_ipsw_file(str(bin_path)) is False


def test_diff_ipsw_detects_version_and_payload_changes(tmp_path):
    old_ipsw = tmp_path / "old.ipsw"
    new_ipsw = tmp_path / "new.ipsw"

    _create_dummy_ipsw(
        old_ipsw,
        "18.0",
        "22A3354",
        {
            "kernelcache.release.iPhone16": b"KERNEL_V1",
            "Firmware/all_flash/sep-firmware.img4": b"SEP_OLD",
            "Firmware/baseband.bbfw": b"BB_V1",
            "removed_daemon.plist": b"OLD_CONFIG",
        },
    )

    _create_dummy_ipsw(
        new_ipsw,
        "18.1",
        "22B83",
        {
            "kernelcache.release.iPhone16": b"KERNEL_V2_LONGER_CONTENT",
            "Firmware/all_flash/sep-firmware.img4": b"SEP_NEW",
            "Firmware/baseband.bbfw": b"BB_V1",
            "cryptex-system-arm64e.dmg": b"NEW_CRYPTEX_DMG",
        },
    )

    result = diff_ipsw(str(old_ipsw), str(new_ipsw))

    assert result["kind"] == "ipsw_diff"
    assert result["build_changes"]["old_product_version"] == "18.0"
    assert result["build_changes"]["new_product_version"] == "18.1"
    assert result["build_changes"]["version_changed"] is True

    comp = result["component_changes"]
    assert comp["total_added"] == 1
    assert "cryptex-system-arm64e.dmg" in comp["added_by_category"]["cryptex"]
    assert comp["total_removed"] == 1
    assert "removed_daemon.plist" in comp["removed_by_category"]["manifests"]
    assert comp["total_modified"] == 3  # BuildManifest.plist, kernelcache, and sep-firmware

    assert "kernel" in result["security_hotspots"]
    assert "secure_enclave" in result["security_hotspots"]
    assert "cryptex" in result["security_hotspots"]

    # Test LLM evidence formatting
    evidence = llm_ipsw_evidence(result)
    assert evidence["evidence_type"] == "ipsw_firmware_diff"
    assert evidence["firmware_transition"]["from_version"] == "18.0"
    assert evidence["firmware_transition"]["to_version"] == "18.1"
    assert evidence["summary_counts"]["components_added"] == 1

    # Test display rendering
    with patch("sys.stdout", new=io.StringIO()):
        display_ipsw_diff(result)
