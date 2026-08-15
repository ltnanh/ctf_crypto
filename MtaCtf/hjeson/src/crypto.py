import base64
import os
from Cryptodome.Cipher import AES



class CryptoSession:
    def __init__(self):
        self.aes_session_key = None
        self.iv = os.urandom(16)

    def encrypt(self, reponse_str: str, aes_session_key: str) -> str:
        aes_session_key = bytes.fromhex(aes_session_key)
        cipher_aes = AES.new(aes_session_key, AES.MODE_OFB, iv=self.iv)
        ciphertext = cipher_aes.encrypt(reponse_str.encode())
        result = cipher_aes.iv + ciphertext
        return base64.b64encode(result).decode()
    def decrypt(self, encrypted_str: str, aes_session_key: str) -> str:
        aes_session_key = bytes.fromhex(aes_session_key)
        data = base64.b64decode(encrypted_str)
        iv = data[:16]
        ciphertext = data[16:]
        cipher_aes = AES.new(aes_session_key, AES.MODE_OFB, iv=iv)
        decrypted = cipher_aes.decrypt(ciphertext)
        try:
            return decrypted.decode()
        except UnicodeDecodeError:
            return base64.b64encode(decrypted).decode() 