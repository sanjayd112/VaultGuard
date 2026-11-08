"""AES-256-GCM encryption helpers for VaultGuard.

Blob layout on disk:  b"VGE1" | 12-byte nonce | ciphertext | 16-byte GCM tag
The key is read from the ENCRYPTION_KEY environment variable (never stored in SQLite).
"""
import base64
import binascii
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"VGE1"
KEY_SIZE = 32      # 256-bit
NONCE_SIZE = 12    # 96-bit, recommended for GCM
TAG_SIZE = 16


class ConfigurationError(RuntimeError):
    """Raised when the encryption key is missing or malformed."""


class DecryptionError(Exception):
    """Raised when authentication fails or the blob is malformed (tampering/corruption)."""


def generate_key() -> str:
    """Return a new random 256-bit key (base64) suitable for ENCRYPTION_KEY."""
    return base64.urlsafe_b64encode(os.urandom(KEY_SIZE)).decode()


def load_key(raw) -> bytes:
    """Decode ENCRYPTION_KEY (base64 or hex) into exactly 32 bytes, or stop securely."""
    if not raw or not raw.strip():
        raise ConfigurationError(
            "ENCRYPTION_KEY is not configured. Run 'python init_env.py' or set the "
            "ENCRYPTION_KEY environment variable (see README)."
        )
    raw = raw.strip()
    for decoder in (base64.urlsafe_b64decode, base64.b64decode, bytes.fromhex):
        try:
            candidate = decoder(raw)
        except (binascii.Error, ValueError):
            continue
        if len(candidate) == KEY_SIZE:
            return candidate
    raise ConfigurationError("ENCRYPTION_KEY is invalid: it must be a 256-bit (32-byte) key, base64 or hex encoded.")


def generate_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digests_match(a: str, b: str) -> bool:
    return hmac.compare_digest(a or "", b or "")


def encrypt(plaintext: bytes, key: bytes, aad: bytes, nonce: bytes = None):
    """Encrypt with AES-256-GCM. Returns (blob, nonce). Never reuse a nonce with the same key."""
    if len(key) != KEY_SIZE:
        raise ConfigurationError("Encryption key must be 32 bytes.")
    nonce = nonce or generate_nonce()
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be 96 bits.")
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return MAGIC + nonce + ciphertext_and_tag, nonce


def decrypt(blob: bytes, key: bytes, aad: bytes) -> bytes:
    """Verify the GCM authentication tag and decrypt. Raises DecryptionError on any problem."""
    if len(key) != KEY_SIZE:
        raise ConfigurationError("Encryption key must be 32 bytes.")
    if len(blob) < len(MAGIC) + NONCE_SIZE + TAG_SIZE or not blob.startswith(MAGIC):
        raise DecryptionError("Encrypted file is malformed or truncated.")
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_SIZE]
    body = blob[len(MAGIC) + NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, body, aad)
    except InvalidTag:
        raise DecryptionError("AES-GCM authentication failed: data was modified or the key/context is wrong.") from None
