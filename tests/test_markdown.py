from poirot.markdown import generate_markdown_report


def test_markdown_binary_diff_report():
    sample_report = {
        "observed_facts": {
            "old": {"path": "v1.bin", "format": "Mach-O", "architecture": "arm64"},
            "new": {"path": "v2.bin", "format": "Mach-O", "architecture": "arm64"},
        },
        "function_changes": {
            "added": ["new_feature"],
            "removed": ["legacy_func"],
            "modified": [
                {
                    "function": "auth_check",
                    "demangled_name": "AuthManager.check()",
                    "change_significance": 75,
                    "evidence": {"size_delta_bytes": 100, "calls_added": 1, "calls_removed": 0, "size_change_ratio": 0.25},
                }
            ],
            "unchanged": ["init"],
            "ambiguous_names_not_matched": [],
        },
        "security_signals_delta": {
            "has_changes": True,
            "added_categories": [{"category": "ipc_xpc", "rationale": "IPC added"}],
            "expanded_categories": [],
            "removed_categories": [],
        },
        "entitlements_delta": {
            "has_changes": True,
            "security_alerts": ["Private entitlement added: com.apple.private.test"],
            "added": {"com.apple.private.test": True},
            "removed": {},
            "modified": {},
        },
    }

    md = generate_markdown_report(sample_report)
    assert "# Poirot — Binary Differential Report" in md
    assert "AuthManager.check()" in md
    assert "ipc_xpc" in md
    assert "com.apple.private.test" in md


def test_markdown_ipsw_diff_report():
    sample_ipsw_report = {
        "kind": "ipsw_diff",
        "old_archive": {"path": "old.ipsw", "product_version": "18.0", "build_number": "22A1", "total_members": 10},
        "new_archive": {"path": "new.ipsw", "product_version": "18.1", "build_number": "22B1", "total_members": 12},
        "build_changes": {},
        "component_changes": {
            "total_added": 2,
            "total_removed": 0,
            "total_modified": 1,
            "total_unchanged": 9,
            "modified_components": [
                {
                    "filename": "kernelcache.release.iPhone16",
                    "category": "kernel",
                    "size_delta_bytes": 2048,
                    "old_crc": "0x12345678",
                    "new_crc": "0x87654321",
                }
            ],
        },
        "security_hotspots": ["kernel"],
    }

    md = generate_markdown_report(sample_ipsw_report)
    assert "# Poirot — IPSW Firmware Differential Report" in md
    assert "kernelcache.release.iPhone16" in md
    assert "iOS 18.0" in md or "18.0" in md
