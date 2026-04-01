from pydantic import BaseModel, Field


class SSHConnection(BaseModel):
    host: str
    port: int = 22
    user: str
    identity_file: str
    timeout: int = 30
    known_hosts: str | None = None
