import datetime
import json
import os
import time
from datetime import timezone
from typing import Any

import hvac
import jwt
from cryptography.fernet import Fernet


class LocalSecretStore:
    """
    Manages secrets in a local encrypted file for development.
    """

    def __init__(self, file_path: str, encryption_key: bytes):
        self.file_path = file_path
        self.cipher = Fernet(encryption_key)
        self._cache = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.file_path):
            self._cache = {}
            return

        try:
            with open(self.file_path, "rb") as f:
                encrypted_data = f.read()
            if not encrypted_data:
                self._cache = {}
                return
            decrypted_data = self.cipher.decrypt(encrypted_data)
            self._cache = json.loads(decrypted_data.decode())
        except Exception as e:
            print(f"Failed to load local secrets: {e}")
            self._cache = {}

    def save(self):
        data = json.dumps(self._cache).encode()
        encrypted_data = self.cipher.encrypt(data)
        with open(self.file_path, "wb") as f:
            f.write(encrypted_data)

    def set_secret(self, key: str, value: str):
        self._cache[key] = value
        self.save()

    def get_secret(self, key: str) -> str | None:
        return self._cache.get(key)


class SecurityUtils:
    _instance = None

    def __init__(
        self,
        vault_url: str | None = None,
        vault_token: str | None = None,
        local_mode: bool = False,
        local_secret_file: str = "secrets.enc",
        cache_ttl: int = 300,
    ):
        """
        :param vault_url: URL of HashiCorp Vault.
        :param vault_token: Token for Vault.
        :param local_mode: If True, uses local encrypted file instead of Vault.
        :param local_secret_file: Path to local encrypted secret file.
        :param cache_ttl: Cache duration in seconds (default 5 mins).
        """
        # Master Key Management
        # In prod, this might come from Env Vars injected by orchestration
        key = os.getenv("ENCRYPTION_KEY")
        if not key:
            # For dev convenience, generate one if missing (warn user)
            key = Fernet.generate_key().decode()
            if local_mode:
                print(f"WARNING: No ENCRYPTION_KEY set. Generated temporary key: {key}")

        self.encryption_key = key.encode()
        self.cipher_suite = Fernet(self.encryption_key)

        self.local_mode = local_mode
        self.vault_client = None
        self.local_store = None
        self.cache_ttl = cache_ttl
        # Cache structure: {lookup_key: (value, timestamp)}
        self._secret_cache: dict[str, tuple[str | None, float]] = {}

        if self.local_mode:
            self.local_store = LocalSecretStore(local_secret_file, self.encryption_key)
        else:
            # Default to localhost if not provided, for easier instantiation
            url = vault_url or os.getenv("VAULT_ADDR", "http://localhost:8200")
            token = vault_token or os.getenv("VAULT_TOKEN")
            self.vault_client = hvac.Client(url=url, token=token)

    def get_secret(self, path: str, key: str = "value") -> str | None:
        """
        Retrieves a secret with caching.
        """
        # Handle "path:key" syntax if provided in first arg
        if ":" in path and key == "value":
            parts = path.split(":", 1)
            path = parts[0]
            key = parts[1]

        lookup_key = f"{path}:{key}"
        current_time = time.time()

        # Check Cache
        if lookup_key in self._secret_cache:
            val, timestamp = self._secret_cache[lookup_key]
            if current_time - timestamp < self.cache_ttl:
                return val

        # Fetch from Source
        secret_value = None
        if self.local_mode:
            secret_value = self.local_store.get_secret(lookup_key)
            if secret_value is None:
                secret_value = self.local_store.get_secret(key)
        else:
            try:
                if self.vault_client.is_authenticated():
                    response = self.vault_client.secrets.kv.v2.read_secret_version(
                        path=path
                    )
                    secret_value = response["data"]["data"].get(key)
            except Exception as e:
                print(f"Error fetching secret from Vault: {e}")
                return None

        # Update Cache
        self._secret_cache[lookup_key] = (secret_value, current_time)
        return secret_value

    def set_secret(self, path: str, key: str, value: str):
        """
        Sets a secret and updates the cache.
        """
        lookup_key = f"{path}:{key}"

        if self.local_mode:
            self.local_store.set_secret(lookup_key, value)
        else:
            try:
                data = {key: value}
                self.vault_client.secrets.kv.v2.create_or_update_secret(
                    path=path, secret=data
                )
            except Exception as e:
                print(f"Error writing secret to Vault: {e}")

        # Update Cache immediately so we see our own write
        self._secret_cache[lookup_key] = (value, time.time())

    def encrypt_data(self, data: str) -> str:
        if not data:
            return ""
        return self.cipher_suite.encrypt(data.encode()).decode()

    def decrypt_data(self, token: str) -> str:
        if not token:
            return ""
        return self.cipher_suite.decrypt(token.encode()).decode()

    def generate_token(self, payload: dict[str, Any], expiry_minutes: int = 60) -> str:
        """
        Generates a JWT token.
        """
        # Use encryption key as secret or a specific JWT secret
        # For simplicity, using the encryption key (ensure it is safe for HMAC if using HS256)
        # Ideally, fetch a specific JWT_SECRET from Vault/Env
        secret = os.getenv("JWT_SECRET", self.encryption_key.decode())

        payload = payload.copy()
        payload["exp"] = datetime.datetime.now(timezone.utc) + datetime.timedelta(
            minutes=expiry_minutes
        )

        return jwt.encode(payload, secret, algorithm="HS256")

    def verify_token(self, token: str) -> dict[str, Any] | None:
        """
        Verifies a JWT token.
        """
        secret = os.getenv("JWT_SECRET", self.encryption_key.decode())
        try:
            return jwt.decode(token, secret, algorithms=["HS256"])
        except jwt.PyJWTError as e:
            print(f"JWT Verification failed: {e}")
            return None

    @classmethod
    def get_instance(cls):
        return cls._instance


def initialize_security(
    vault_url: str | None = None,
    vault_token: str | None = None,
    local_mode: bool = False,
    local_secret_file: str = "secrets.enc",
):
    SecurityUtils._instance = SecurityUtils(
        vault_url, vault_token, local_mode, local_secret_file
    )


def get_secret(name: str) -> str | None:
    """
    Convenience wrapper.
    Usage: get_secret("db_creds:password")
    """
    instance = SecurityUtils.get_instance()
    if not instance:
        raise RuntimeError(
            "Security module not initialized. Call initialize_security() first."
        )

    if ":" in name:
        path, key = name.split(":", 1)
        return instance.get_secret(path, key)
    else:
        return instance.get_secret(name, "value")


def set_secret(path: str, key: str, value: str):
    """Global wrapper for set_secret."""
    instance = SecurityUtils.get_instance()
    if not instance:
        raise RuntimeError("Security module not initialized.")
    instance.set_secret(path, key, value)


def encrypt_data(data: str) -> str:
    """Global wrapper for encrypt_data."""
    instance = SecurityUtils.get_instance()
    if not instance:
        raise RuntimeError("Security module not initialized.")
    return instance.encrypt_data(data)


def decrypt_data(token: str) -> str:
    """Global wrapper for decrypt_data."""
    instance = SecurityUtils.get_instance()
    if not instance:
        raise RuntimeError("Security module not initialized.")
    return instance.decrypt_data(token)


def generate_token(payload: dict[str, Any], expiry_minutes: int = 60) -> str:
    """Global wrapper for generate_token."""
    instance = SecurityUtils.get_instance()
    if not instance:
        raise RuntimeError("Security module not initialized.")
    return instance.generate_token(payload, expiry_minutes)


def verify_token(token: str) -> dict[str, Any] | None:
    """Global wrapper for verify_token."""
    instance = SecurityUtils.get_instance()
    if not instance:
        raise RuntimeError("Security module not initialized.")
    return instance.verify_token(token)
