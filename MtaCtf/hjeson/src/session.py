import base64
from hashlib import sha256
import json
import secrets

from Cryptodome.Random import get_random_bytes
from models import Session


class SessionManager:
    def __init__(self):
        self.salt = b"**********"
        assert len(self.salt) == 10
    def hash_calculate(self, session: Session) -> str:
        session_dict = {
            "session_id": session.session_id,
            "username": session.username,
            "role": session.role,
            "aes_session_key": session.aes_session_key,
        }
        session_json = json.dumps(session_dict, sort_keys=True)
        return sha256(self.salt  +  session_json.encode()).hexdigest()
    def create_session(
        self,
        username: str,
        role: str,
        aes_session_key: bytes,
    ) -> Session:
        session = Session(
            session_id=secrets.token_hex(16),
            username=username,
            role=role,
            aes_session_key=aes_session_key,
        )
        session.session_hash= self.hash_calculate(session)
        return session

    def validate_session(self, session: Session) -> bool:
        expected_hash = self.hash_calculate(session)
        return expected_hash == session.session_hash
