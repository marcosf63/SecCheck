from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import paramiko

from app.models.connection import SSHConnection
from app.ssh.client import SSHClient
from app.ssh.errors import AuthenticationError, SSHConnectionError


@pytest.fixture
def connection(tmp_path):
    key_file = tmp_path / "id_ed25519"
    key_file.write_text("fake key")
    return SSHConnection(host="10.0.0.1", port=22, user="ubuntu", identity_file=str(key_file))


def test_connect_raises_if_key_not_found():
    conn = SSHConnection(host="10.0.0.1", port=22, user="ubuntu", identity_file="/nonexistent/key")
    client = SSHClient(conn)
    with pytest.raises(SSHConnectionError, match="Chave privada não encontrada"):
        client.connect()


@patch("app.ssh.client.paramiko.SSHClient")
def test_connect_raises_on_auth_failure(mock_paramiko_cls, connection):
    mock_instance = MagicMock()
    mock_paramiko_cls.return_value = mock_instance
    mock_instance.connect.side_effect = paramiko.AuthenticationException()

    client = SSHClient(connection)
    with pytest.raises(AuthenticationError):
        client.connect()


@patch("app.ssh.client.paramiko.SSHClient")
def test_connect_raises_on_socket_error(mock_paramiko_cls, connection):
    import socket
    mock_instance = MagicMock()
    mock_paramiko_cls.return_value = mock_instance
    mock_instance.connect.side_effect = socket.error("timeout")

    client = SSHClient(connection)
    with pytest.raises(SSHConnectionError):
        client.connect()


@patch("app.ssh.client.paramiko.SSHClient")
def test_connect_success(mock_paramiko_cls, connection):
    mock_instance = MagicMock()
    mock_paramiko_cls.return_value = mock_instance

    client = SSHClient(connection)
    client.connect()

    assert client._client is not None
    mock_instance.connect.assert_called_once()


@patch("app.ssh.client.paramiko.SSHClient")
def test_context_manager_calls_disconnect(mock_paramiko_cls, connection):
    mock_instance = MagicMock()
    mock_paramiko_cls.return_value = mock_instance

    with SSHClient(connection):
        pass

    mock_instance.close.assert_called_once()


@patch("app.ssh.client.paramiko.SSHClient")
def test_raw_raises_when_not_connected(mock_paramiko_cls, connection):
    client = SSHClient(connection)
    with pytest.raises(SSHConnectionError, match="Não conectado"):
        _ = client.raw
