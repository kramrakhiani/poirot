import json

from poirot.config import load_config, save_config, is_configured, DEFAULTS


def test_load_config_returns_defaults_when_no_file(tmp_path, monkeypatch):
    monkeypatch.setattr("poirot.config.CONFIG_FILE", tmp_path / "nonexistent" / "config.json")
    config = load_config()
    assert config["provider"] is None
    assert config["allow_cloud"] is False


def test_save_and_load_round_trip(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    monkeypatch.setattr("poirot.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("poirot.config.CONFIG_FILE", config_file)

    saved = {"provider": "openrouter", "model": None, "allow_cloud": True, "timeout": None}
    save_config(saved)
    assert config_file.exists()

    loaded = load_config()
    assert loaded["provider"] == "openrouter"
    assert loaded["allow_cloud"] is True


def test_is_configured_false_when_no_file(tmp_path, monkeypatch):
    monkeypatch.setattr("poirot.config.CONFIG_FILE", tmp_path / "nope.json")
    assert is_configured() is False


def test_is_configured_true_after_save(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    monkeypatch.setattr("poirot.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("poirot.config.CONFIG_FILE", config_file)

    save_config({"provider": "ollama", "model": None, "allow_cloud": False, "timeout": None})
    assert is_configured() is True


def test_corrupt_config_file_returns_defaults(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    config_file.write_text("not valid json!!!", encoding="utf-8")
    monkeypatch.setattr("poirot.config.CONFIG_FILE", config_file)

    config = load_config()
    assert config == DEFAULTS
