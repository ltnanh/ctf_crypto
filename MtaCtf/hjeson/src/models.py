from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class User:
    username: str
    role: str = "user"
    password_hash: Optional[str] = None


@dataclass
class Product:
    owner: str
    name: str
    description: str

@dataclass
class Session:
    session_id: str
    username: str
    role: str
    aes_session_key: bytes
    session_hash: Optional[str] = None
    

@dataclass
class Request:
    method: str
    params: dict = field(default_factory=dict)


@dataclass
class Response:
    status: str
    data: Optional[dict] = None
    error: Optional[str] = None
