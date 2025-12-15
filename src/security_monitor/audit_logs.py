import hashlib
import json
import logging
import os
import re
import time
from logging.handlers import RotatingFileHandler
from typing import Any


class LogMasker:
    # Regex patterns
    EMAIL_REGEX = r"(?P<prefix>[\w\.-]+)@(?P<domain>[\w\.-]+)"
    PHONE_REGEX = r"(?<!\w)(\+?[\d\s-]{10,})(?!\w)"
    # Simple Credit Card Regex (matches 13-19 digits, possibly separated by - or space)
    CC_REGEX = r"(?:\d[ -]*?){13,16}"
    # SSN Regex (US format: ddd-dd-dddd)
    SSN_REGEX = r"\d{3}-\d{2}-\d{4}"

    @staticmethod
    def mask_email(text: str) -> str:
        def replace(match):
            prefix = match.group("prefix")
            domain = match.group("domain")
            # Mask first 3 chars if len > 3, else all but last
            masked_prefix = prefix[0] + "***" + prefix[-1] if len(prefix) > 2 else "***"
            return f"{masked_prefix}@{domain}"

        return re.sub(LogMasker.EMAIL_REGEX, replace, text)

    @staticmethod
    def mask_phone(text: str) -> str:
        # Mask all but last 4 digits
        def replace(match):
            num = match.group(0)
            clean = "".join(filter(str.isdigit, num))
            if len(clean) < 4:
                return "***"
            return "***-" + clean[-4:]

        return re.sub(LogMasker.PHONE_REGEX, replace, text)

    @staticmethod
    def mask_cc(text: str) -> str:
        def replace(match):
            s = match.group(0)
            clean = "".join(filter(str.isdigit, s))
            if len(clean) < 4:
                return "***"
            return "***-" + clean[-4:]

        return re.sub(LogMasker.CC_REGEX, replace, text)

    @staticmethod
    def mask_ssn(text: str) -> str:
        return re.sub(LogMasker.SSN_REGEX, "***-**-****", text)

    @staticmethod
    def mask_data(data: Any) -> Any:
        """
        Recursively masks sensitive data in dicts/lists/strings.
        """
        if isinstance(data, str):
            masked = LogMasker.mask_email(data)
            masked = LogMasker.mask_phone(masked)
            masked = LogMasker.mask_cc(masked)
            masked = LogMasker.mask_ssn(masked)
            return masked
        elif isinstance(data, dict):
            return {k: LogMasker.mask_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [LogMasker.mask_data(i) for i in data]
        return data


class AuditLogger:
    def __init__(
        self,
        log_file: str = "audit_logs.jsonl",
        mask_sensitive: bool = True,
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 5,
    ):
        self.log_file = log_file
        self.mask_sensitive = mask_sensitive
        self.last_hash = "0" * 64  # Genesis hash

        # Initialize last_hash from file if exists
        self._init_last_hash()

        # Setup Logger
        # Use a unique logger name per file to avoid handler conflicts
        self.logger = logging.getLogger(f"AuditLogger_{os.path.abspath(log_file)}")
        self.logger.setLevel(logging.INFO)

        # Avoid adding duplicate handlers if re-instantiated
        if not self.logger.handlers:
            handler = RotatingFileHandler(
                log_file, maxBytes=max_bytes, backupCount=backup_count
            )
            formatter = logging.Formatter(
                "%(message)s"
            )  # We just want the JSON message
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def _init_last_hash(self):
        """Reads the last line of the log file to get the previous hash."""
        if not os.path.exists(self.log_file):
            return

        try:
            with open(self.log_file, "rb") as f:
                try:
                    f.seek(-2, os.SEEK_END)
                    while f.read(1) != b"\n":
                        f.seek(-2, os.SEEK_CUR)
                except OSError:
                    f.seek(0)
                last_line = f.readline().decode()

            if last_line:
                entry = json.loads(last_line)
                self.last_hash = entry.get("hash", "0" * 64)
        except Exception:
            # If file is empty or corrupted, start over or keep genesis
            pass

    def log_event(
        self, user: str, action: str, result: str, details: dict[str, Any] | None = None
    ):
        """
        Logs a key operation event in JSONL format with hash chaining.
        """
        details_safe = details or {}
        if self.mask_sensitive:
            details_safe = LogMasker.mask_data(details_safe)
            user = LogMasker.mask_data(user)  # In case user is email

        event_data = {
            "timestamp": time.time(),
            "user": user,
            "action": action,
            "result": result,
            "details": details_safe,
        }

        # Calculate Hash
        # Canonical string: prev_hash + sorted json of event content
        canonical_str = f"{self.last_hash}{json.dumps(event_data, sort_keys=True)}"
        current_hash = hashlib.sha256(canonical_str.encode()).hexdigest()

        event_data["hash"] = current_hash
        self.last_hash = current_hash

        # Use logger which handles rotation
        self.logger.info(json.dumps(event_data))

    def query_logs(self, user: str | None = None, action: str | None = None) -> list:
        """
        Simple query mechanism for logs.
        WARNING: This only reads the CURRENT active log file, not rotated backups.
        For a full audit query, one should ideally iterate over rotated logs too.
        For this scope, we stick to the primary file or user guidance.
        """
        results = []
        if not os.path.exists(self.log_file):
            return results

        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if user and entry.get("user") != user:
                        continue
                    if action and entry.get("action") != action:
                        continue
                    results.append(entry)
                except json.JSONDecodeError:
                    continue
        return results

    def verify_integrity(self) -> bool:
        """
        Verifies the cryptographic integrity of the log file.
        Returns True if the hash chain is valid, False otherwise.
        """
        if not os.path.exists(self.log_file):
            return True

        prev_hash = "0" * 64
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        print(
                            f"Integrity Check Failed: Invalid JSON on line {line_num}"
                        )
                        return False

                    stored_hash = entry.get("hash")
                    if not stored_hash:
                        print(
                            f"Integrity Check Failed: No hash found on line {line_num}"
                        )
                        return False

                    # Reconstruct event data to verify hash
                    event_data = entry.copy()
                    del event_data["hash"]

                    canonical_str = (
                        f"{prev_hash}{json.dumps(event_data, sort_keys=True)}"
                    )
                    calculated_hash = hashlib.sha256(canonical_str.encode()).hexdigest()

                    if calculated_hash != stored_hash:
                        print(
                            f"Integrity Check Failed: Hash mismatch on line {line_num}"
                        )
                        print(f"Expected: {calculated_hash}")
                        print(f"Found:    {stored_hash}")
                        return False

                    prev_hash = stored_hash

            return True
        except Exception as e:
            print(f"Integrity Check Failed: Error reading file {e}")
            return False
