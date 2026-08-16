import plistlib
import struct
from poirot.entitlements import (
    CSMAGIC_EMBEDDED_ENTITLEMENTS,
    CSMAGIC_EMBEDDED_SUPERBLOB,
    diff_entitlements,
    extract_entitlements_from_file,
)


def test_extract_xml_plist_entitlements(tmp_path):
    ent_data = {
        "com.apple.security.app-sandbox": True,
        "com.apple.private.tcc.allow": ["kTCCServiceCamera"],
    }
    xml_blob = plistlib.dumps(ent_data)
    binary_file = tmp_path / "app_with_entitlements"
    binary_file.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 64 + xml_blob + b"\x00" * 32)

    extracted = extract_entitlements_from_file(binary_file)
    assert extracted.get("com.apple.security.app-sandbox") is True
    assert extracted.get("com.apple.private.tcc.allow") == ["kTCCServiceCamera"]


def test_diff_entitlements_detects_security_alerts():
    old_ent = {
        "com.apple.security.app-sandbox": True,
        "get-task-allow": False,
    }
    new_ent = {
        "com.apple.security.app-sandbox": False,
        "com.apple.private.tcc.allow": ["kTCCServiceMicrophone"],
    }

    diff = diff_entitlements(old_ent, new_ent)
    assert diff["has_changes"] is True
    assert "com.apple.private.tcc.allow" in diff["added"]
    assert "get-task-allow" in diff["removed"]
    assert "com.apple.security.app-sandbox" in diff["modified"]

    # Security alert check
    assert any("private" in a.lower() for a in diff["security_alerts"])
