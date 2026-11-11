"""Default configuration must work in both a checkout and an installed wheel."""
import pytest

from maestro import config
from maestro.maestro.threats import load_threats


def test_config_reader_uses_packaged_defaults_when_checkout_is_absent(monkeypatch, tmp_path):
    packaged = tmp_path / "package"
    path = packaged / "resources/configs"
    path.mkdir(parents=True)
    (path / "default.yaml").write_text("server:\n  port: 9123\n", encoding="utf-8")
    monkeypatch.setattr(config, "_REPO_ROOT", tmp_path / "absent")
    monkeypatch.setattr(config, "files", lambda name: packaged)
    assert config.load_config().server.port == 9123


def test_threat_defaults_remain_readable_without_checkout(monkeypatch, tmp_path):
    packaged = tmp_path / "package"
    path = packaged / "resources/configs"
    path.mkdir(parents=True)
    (path / "threats.yaml").write_text(config.config_text("threats.yaml"), encoding="utf-8")
    monkeypatch.setattr(config, "_REPO_ROOT", tmp_path / "absent")
    monkeypatch.setattr(config, "files", lambda name: packaged)
    assert len(load_threats()) == 10


def test_default_reader_rejects_path_traversal():
    with pytest.raises(ValueError):
        config.config_text("../secret.yaml")
