import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import sys

load_dotenv()

_key = os.getenv("ENCRYPTION_KEY")
if not _key:
    print("ERROR: ENCRYPTION_KEY environment variable is not set!")
    print("Please set it to a secure base64-encoded key (e.g., via 'python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"')")
    sys.exit(1)

try:
    _fernet = Fernet(_key.encode())
except Exception as e:
    print(f"ERROR: Invalid ENCRYPTION_KEY: {e}")
    sys.exit(1)

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
