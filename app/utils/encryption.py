import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

_key = os.getenv("ENCRYPTION_KEY")
if not _key:
    _key = Fernet.generate_key().decode()
    os.environ["ENCRYPTION_KEY"] = _key

_fernet = Fernet(_key.encode())

def encrypt_pii(text: str | None) -> str | None:
    if not text:
        return text
    return _fernet.encrypt(text.encode("utf-8")).decode("utf-8")

def decrypt_pii(token: str | None) -> str | None:
    if not token:
        return token
    try:
        return _fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception:
        return token
