class SSHConnectionError(Exception):
    """Falha ao estabelecer conexão SSH."""


class AuthenticationError(SSHConnectionError):
    """Falha de autenticação SSH."""


class CommandExecutionError(Exception):
    """Falha ao executar comando remoto."""
