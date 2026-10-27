"""Anti-forensic proxy mode for operational security.

Per gap analysis item 32: The proxy logs full request/response bodies.
If the proxy server is seized, the operator's entire campaign is on disk.
This module provides a forensic_safe mode that:
- Disables body logging (no request/response content stored)
- Overwrites session data with zeros on disconnect
- Encrypts the DB at rest with a key that's only in memory
- Implements secure deletion of temporary files

Usage:
    from dropoutjeep_lib.utils.forensic_safe import ForensicSafeConfig, SecureSessionStore
    config = ForensicSafeConfig(enabled=True)
    store = SecureSessionStore(config)
    store.store('session123', {'cookies': [...]})  # encrypted in memory
    store.wipe()  # Overwrite all data with zeros
"""

import base64
import hashlib
import json
import logging
import os
import secrets
import shutil
from typing import Optional

logger = logging.getLogger("dropoutjeep")

# Try to import cryptography for AES
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography not available — DB encryption disabled")


class ForensicSafeConfig:
    """Configuration for anti-forensic proxy mode.

    Attributes:
        enabled: Master switch
        log_bodies: If False, request/response bodies are not logged
        encrypt_db: If True, session data is encrypted at rest
        secure_delete: If True, files are securely overwritten before deletion
        wipe_on_disconnect: If True, session data is zeroed on disconnect
        memory_only: If True, no data is written to disk at all
    """

    def __init__(self, enabled: bool = False, log_bodies: bool = True,
                 encrypt_db: bool = True, secure_delete: bool = True,
                 wipe_on_disconnect: bool = True, memory_only: bool = False):
        self.enabled = enabled
        self.log_bodies = log_bodies if not enabled else False
        self.encrypt_db = encrypt_db if enabled else False
        self.secure_delete = secure_delete if enabled else False
        self.wipe_on_disconnect = wipe_on_disconnect if enabled else False
        self.memory_only = memory_only if enabled else False

    @classmethod
    def from_settings(cls):
        """Load config from framework settings."""
        try:
            from dropoutjeep_lib.utils.settings import get_setting
            return cls(
                enabled=get_setting('forensic_safe', False),
                log_bodies=get_setting('proxy_log_bodies', True),
                encrypt_db=get_setting('forensic_encrypt_db', True),
                secure_delete=get_setting('forensic_secure_delete', True),
                wipe_on_disconnect=get_setting('forensic_wipe_on_disconnect', True),
                memory_only=get_setting('forensic_memory_only', False),
            )
        except Exception:
            return cls(enabled=False)

    def to_dict(self) -> dict:
        return {
            'enabled': self.enabled,
            'log_bodies': self.log_bodies,
            'encrypt_db': self.encrypt_db,
            'secure_delete': self.secure_delete,
            'wipe_on_disconnect': self.wipe_on_disconnect,
            'memory_only': self.memory_only,
        }


class InMemoryKey:
    """Encryption key that lives only in memory.

    Generated on startup, never written to disk. Lost on process exit.
    """

    def __init__(self):
        self._key = secrets.token_bytes(32)  # 256-bit key
        self._salt = secrets.token_bytes(16)

    def get_fernet_key(self) -> bytes:
        """Derive a Fernet-compatible key from the in-memory key."""
        if not CRYPTO_AVAILABLE:
            return b''
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
        )
        derived = kdf.derive(self._key)
        return base64.urlsafe_b64encode(derived)

    def wipe(self):
        """Securely overwrite the key in memory."""
        for i in range(len(self._key)):
            self._key = self._key[:i] + b'\x00' + self._key[i+1:]
        self._key = b'\x00' * 32
        self._salt = b'\x00' * 16


class SecureSessionStore:
    """In-memory encrypted session store for forensic-safe mode.

    Session data (cookies, credentials, request/response logs) is stored
    in memory only, encrypted with the in-memory key. No disk writes.
    """

    def __init__(self, config: ForensicSafeConfig):
        self.config = config
        self._sessions: dict[str, bytes] = {}  # session_id -> encrypted data
        self._key = InMemoryKey()
        self._fernet = None
        if CRYPTO_AVAILABLE and config.encrypt_db:
            fernet_key = self._key.get_fernet_key()
            if fernet_key:
                self._fernet = Fernet(fernet_key)

    def store(self, session_id: str, data: dict) -> bool:
        """Store session data (encrypted in memory).

        Args:
            session_id: Session identifier
            data: Session data dict (cookies, credentials, etc.)

        Returns:
            True if stored successfully.
        """
        try:
            raw = json.dumps(data, default=str).encode('utf-8')
            if self._fernet:
                encrypted = self._fernet.encrypt(raw)
            else:
                encrypted = raw
            self._sessions[session_id] = encrypted
            return True
        except Exception as e:
            logger.error("SecureSessionStore store error: %s", e)
            return False

    def retrieve(self, session_id: str) -> Optional[dict]:
        """Retrieve and decrypt session data."""
        encrypted = self._sessions.get(session_id)
        if not encrypted:
            return None
        try:
            if self._fernet:
                raw = self._fernet.decrypt(encrypted)
            else:
                raw = encrypted
            return json.loads(raw.decode('utf-8'))
        except Exception as e:
            logger.error("SecureSessionStore retrieve error: %s", e)
            return None

    def wipe_session(self, session_id: str):
        """Securely overwrite a single session's data."""
        if session_id in self._sessions:
            # Overwrite with zeros
            data = self._sessions[session_id]
            zeroed = b'\x00' * len(data)
            self._sessions[session_id] = zeroed
            del self._sessions[session_id]

    def wipe_all(self):
        """Securely overwrite ALL session data."""
        for session_id in list(self._sessions.keys()):
            self.wipe_session(session_id)
        logger.info("SecureSessionStore: all sessions wiped (%d sessions)", len(self._sessions))

    def list_sessions(self) -> list[str]:
        """List all session IDs (without decrypting data)."""
        return list(self._sessions.keys())

    def destroy(self):
        """Destroy the store entirely — wipe all data and the encryption key."""
        self.wipe_all()
        self._key.wipe()
        self._fernet = None
        self._sessions.clear()
        logger.info("SecureSessionStore destroyed")


def secure_delete_file(filepath: str, passes: int = 3):
    """Securely overwrite and delete a file.

    Overwrites the file with random data multiple times before deletion.

    Args:
        filepath: Path to the file
        passes: Number of overwrite passes (default 3)
    """
    if not os.path.exists(filepath):
        return

    try:
        file_size = os.path.getsize(filepath)

        with open(filepath, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())

        os.remove(filepath)
        logger.info("Securely deleted: %s (%d bytes, %d passes)",
                    filepath, file_size, passes)
    except Exception as e:
        logger.warning("Secure delete failed for %s: %s", filepath, e)
        try:
            os.remove(filepath)
        except Exception:
            pass


def secure_delete_directory(dirpath: str, passes: int = 3):
    """Securely delete all files in a directory, then the directory itself."""
    if not os.path.exists(dirpath):
        return

    for root, dirs, files in os.walk(dirpath, topdown=False):
        for filename in files:
            filepath = os.path.join(root, filename)
            secure_delete_file(filepath, passes)
        for dirname in dirs:
            dir_full = os.path.join(root, dirname)
            try:
                os.rmdir(dir_full)
            except Exception:
                pass

    try:
        os.rmdir(dirpath)
    except Exception:
        shutil.rmtree(dirpath, ignore_errors=True)

    logger.info("Securely deleted directory: %s", dirpath)


def should_log_body(config: ForensicSafeConfig, event_type: str = 'request') -> bool:
    """Check if request/response bodies should be logged based on forensic-safe config."""
    if not config.enabled:
        return True
    if config.memory_only:
        return False
    return config.log_bodies
