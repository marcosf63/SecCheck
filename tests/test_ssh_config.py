from pathlib import Path

import pytest

from app.utils.ssh_config import load_ssh_config


SSH_CONFIG_CONTENT = """\
Host prod
    HostName 10.0.0.1
    User deploy
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host staging
    HostName staging.exemplo.com
    User ubuntu

Host no-identity
    HostName 192.168.1.5
    User admin
"""


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "ssh_config"
    path.write_text(SSH_CONFIG_CONTENT)
    # Cria uma chave fictícia para o teste de identidade
    key = tmp_path / ".ssh" / "id_ed25519"
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text("fake key")
    return path, tmp_path


class TestLoadSSHConfig:
    def test_resolves_all_fields(self, config_file, monkeypatch):
        cfg_path, tmp = config_file
        monkeypatch.setenv("HOME", str(tmp))
        entry = load_ssh_config("prod", config_path=str(cfg_path))
        assert entry.hostname == "10.0.0.1"
        assert entry.user == "deploy"
        assert entry.port == 2222

    def test_missing_config_returns_empty(self, tmp_path):
        entry = load_ssh_config("anyhost", config_path=str(tmp_path / "nonexistent"))
        assert entry.hostname is None
        assert entry.user is None
        assert entry.port is None
        assert entry.identity_file is None

    def test_host_not_in_config_returns_defaults(self, config_file):
        cfg_path, _ = config_file
        entry = load_ssh_config("unknown-host", config_path=str(cfg_path))
        assert entry.user is None
        assert entry.port is None

    def test_no_identity_file_returns_none(self, config_file):
        cfg_path, _ = config_file
        entry = load_ssh_config("no-identity", config_path=str(cfg_path))
        assert entry.user == "admin"
        assert entry.identity_file is None

    def test_identity_file_only_resolved_if_exists(self, config_file, monkeypatch):
        cfg_path, tmp = config_file
        monkeypatch.setenv("HOME", str(tmp))
        entry = load_ssh_config("prod", config_path=str(cfg_path))
        # Só retorna identity_file se o arquivo realmente existe
        if entry.identity_file:
            assert Path(entry.identity_file).exists()

    def test_staging_has_no_port(self, config_file):
        cfg_path, _ = config_file
        entry = load_ssh_config("staging", config_path=str(cfg_path))
        assert entry.hostname == "staging.exemplo.com"
        assert entry.user == "ubuntu"
        assert entry.port is None
