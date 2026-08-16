import subprocess
import sys


def test_version_flag():
    result = subprocess.run(
        [sys.executable, "-m", "poirot", "--version"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "0.2.0" in result.stdout


def test_setup_command_is_registered():
    result = subprocess.run(
        [sys.executable, "-m", "poirot", "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "setup" in result.stdout


def test_missing_binary_exits_cleanly():
    result = subprocess.run(
        [sys.executable, "-m", "poirot", "analyze", "/nonexistent/binary"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 1
    assert "Error" in result.stderr
    # No raw traceback should appear.
    assert "Traceback" not in result.stderr


def test_ipsw_diff_cli(tmp_path):
    from tests.test_ipsw_diff import _create_dummy_ipsw
    old_ipsw = tmp_path / "v1.ipsw"
    new_ipsw = tmp_path / "v2.ipsw"
    _create_dummy_ipsw(old_ipsw, "18.0", "22A1", {"kernelcache": b"V1"})
    _create_dummy_ipsw(new_ipsw, "18.1", "22B1", {"kernelcache": b"V2"})

    result = subprocess.run(
        [sys.executable, "-m", "poirot", "diff", str(old_ipsw), str(new_ipsw), "--json"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert '"kind": "ipsw_diff"' in result.stdout
    assert '"old_product_version": "18.0"' in result.stdout
    assert '"new_product_version": "18.1"' in result.stdout


def test_completion_command():
    result = subprocess.run(
        [sys.executable, "-m", "poirot", "completion", "zsh"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "_poirot" in result.stdout


def test_ipsw_component_drilldown_cli(tmp_path):
    from tests.test_ipsw_diff import _create_dummy_ipsw
    old_ipsw = tmp_path / "v1.ipsw"
    new_ipsw = tmp_path / "v2.ipsw"
    # Create valid ELF or thin headers inside the IPSWs for component deep-diff
    macho_arm64_old = b"\xcf\xfa\xed\xfe" + (0x0100000C).to_bytes(4, "little") + b"\x00" * 32
    macho_arm64_new = b"\xcf\xfa\xed\xfe" + (0x0100000C).to_bytes(4, "little") + b"\x00" * 64
    _create_dummy_ipsw(old_ipsw, "18.0", "22A1", {"usr/bin/daemon": macho_arm64_old})
    _create_dummy_ipsw(new_ipsw, "18.1", "22B1", {"usr/bin/daemon": macho_arm64_new})

    result = subprocess.run(
        [sys.executable, "-m", "poirot", "diff", str(old_ipsw), str(new_ipsw), "--component", "usr/bin/daemon", "--json"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert '"observed_facts"' in result.stdout
    assert "usr/bin/daemon" in result.stdout


