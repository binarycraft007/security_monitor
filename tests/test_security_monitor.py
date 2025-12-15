import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.fernet import Fernet

from security_monitor.audit_logs import AuditLogger
from security_monitor.monitor_utils import MonitorUtils
from security_monitor.security_utils import (
    LocalSecretStore,
    SecurityUtils,
    get_secret,
    initialize_security,
)


def test_encryption_decryption():
    sec = SecurityUtils(local_mode=True)
    original = "secret_data"
    encrypted = sec.encrypt_data(original)
    assert encrypted != original
    decrypted = sec.decrypt_data(encrypted)
    assert decrypted == original


@patch("hvac.Client")
def test_vault_integration(mock_client):
    # Setup mock
    instance = mock_client.return_value
    instance.is_authenticated.return_value = True
    instance.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"password": "123456"}}
    }

    sec = SecurityUtils(vault_url="http://fake:8200")
    secret = sec.get_secret("db_creds", "password")
    assert secret == "123456"


def test_local_secret_store(tmp_path):
    f = tmp_path / "secrets.enc"

    # Generate valid key
    valid_key = Fernet.generate_key().decode()
    os.environ["ENCRYPTION_KEY"] = valid_key

    sec = SecurityUtils(local_mode=True, local_secret_file=str(f))
    sec.set_secret("db", "password", "local_pass")

    # Reload
    sec2 = SecurityUtils(local_mode=True, local_secret_file=str(f))
    assert sec2.get_secret("db:password") == "local_pass"


def test_monitor_collect_metrics():
    mon = MonitorUtils()
    metrics = mon.collect_system_metrics()
    assert "cpu" in metrics
    assert "memory" in metrics
    assert isinstance(metrics["cpu"], float)


@patch("security_monitor.monitor_utils.ping")
def test_check_service_health(mock_ping):
    mon = MonitorUtils()
    mock_ping.return_value = 0.1
    assert mon.check_service_health("localhost") is True

    mock_ping.return_value = False
    assert mon.check_service_health("deadhost") is False


def test_monitor_alert(caplog):
    mon = MonitorUtils()
    # Mock CPU high
    with patch("psutil.cpu_percent", return_value=85.0):
        mon.collect_system_metrics()
        assert "ALERT: CPU is critical!" in caplog.text


def test_db_query_timer():
    mon = MonitorUtils()
    with mon.db_query_timer():
        time.sleep(0.01)
    # Check if metric updated (hard to check internal prometheus state easily without registry access,
    # but execution without error is good)


# --- Audit Logs Tests ---
def test_audit_logging(tmp_path):
    log_file = tmp_path / "test_audit.jsonl"
    audit = AuditLogger(str(log_file))

    audit.log_event("admin", "login", "success", {"ip": "127.0.0.1"})
    audit.log_event("user1", "download", "fail")

    assert log_file.exists()

    # Query
    logs = audit.query_logs(user="admin")
    assert len(logs) == 1
    assert logs[0]["action"] == "login"
    assert "hash" in logs[0]  # Check hash existence

    logs_all = audit.query_logs()
    assert len(logs_all) == 2
    assert logs_all[1]["hash"] is not None


def test_audit_masking(tmp_path):
    log_file = tmp_path / "test_mask.jsonl"
    audit = AuditLogger(str(log_file), mask_sensitive=True)

    audit.log_event(
        user="test@example.com",
        action="update",
        result="ok",
        details={"phone": "+1-555-0199", "note": "Contact me at alice@corp.com"},
    )

    logs = audit.query_logs()
    entry = logs[0]

    assert "test@example.com" not in entry["user"]  # Should be masked
    assert "@example.com" in entry["user"]

    details = entry["details"]
    assert "+1-555-0199" not in details["phone"]
    assert "***-0199" in details["phone"]
    assert "alice@corp.com" not in details["note"]


def test_audit_chaining_and_integrity(tmp_path):
    log_file = tmp_path / "test_chain.jsonl"
    audit = AuditLogger(str(log_file))

    # Log events
    audit.log_event("u1", "a1", "ok")
    audit.log_event("u2", "a2", "ok")

    # Check integrity
    assert audit.verify_integrity() is True

    # Check persistence
    audit2 = AuditLogger(str(log_file))
    assert audit2.last_hash == audit.last_hash

    audit2.log_event("u3", "a3", "ok")
    assert audit2.verify_integrity() is True


def test_audit_tampering(tmp_path):
    log_file = tmp_path / "test_tamper.jsonl"
    audit = AuditLogger(str(log_file))
    audit.log_event("u1", "a1", "ok")
    audit.log_event("u2", "a2", "ok")

    assert audit.verify_integrity() is True

    # Tamper with the file
    lines = []
    with open(log_file, "r") as f:
        lines = f.readlines()

    # Modify the first entry
    entry = json.loads(lines[0])
    entry["user"] = "hacker"
    # Note: we aren't recomputing hash, so this should fail integrity
    lines[0] = json.dumps(entry) + "\n"

    with open(log_file, "w") as f:
        f.writelines(lines)

    assert audit.verify_integrity() is False


def test_secret_caching():
    # Mock Vault Client
    with patch("hvac.Client") as mock_client:
        instance = mock_client.return_value
        instance.is_authenticated.return_value = True

        # Setup mock to return different values based on call count or time
        # But easier: verify call count
        instance.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"key": "secret_v1"}}
        }

        sec = SecurityUtils(vault_url="http://fake:8200", cache_ttl=1)  # 1 sec TTL

        # First call: hits Vault
        val1 = sec.get_secret("path", "key")
        assert val1 == "secret_v1"
        assert instance.secrets.kv.v2.read_secret_version.call_count == 1

        # Second call immediate: should hit cache (no new Vault call)
        val2 = sec.get_secret("path", "key")
        assert val2 == "secret_v1"
        assert instance.secrets.kv.v2.read_secret_version.call_count == 1

        # Wait for expiry
        time.sleep(1.1)

        # Third call: should hit Vault again
        val3 = sec.get_secret("path", "key")
        assert val3 == "secret_v1"
        assert instance.secrets.kv.v2.read_secret_version.call_count == 2


def test_jwt_generation_verification():
    sec = SecurityUtils(local_mode=True)
    payload = {"user_id": 123, "role": "admin"}
    token = sec.generate_token(payload)

    assert token is not None
    assert isinstance(token, str)

    decoded = sec.verify_token(token)
    assert decoded is not None
    assert decoded["user_id"] == 123
    assert decoded["role"] == "admin"

    # Test invalid token
    assert sec.verify_token("invalid.token.here") is None


@patch("smtplib.SMTP")
def test_alert_sending(mock_smtp):
    email_conf = {"host": "smtp.test", "to": "a@b.com", "from": "c@d.com"}
    mon = MonitorUtils(email_config=email_conf)

    # Mock SMTP context manager
    instance = mock_smtp.return_value
    instance.__enter__.return_value = instance

    mon.alert_manager.send_alert("Subject", "Body")
    instance.send_message.assert_called_once()

    # Trigger via threshold
    mon.alert_manager.check_threshold("CPU", 90.0, 80.0)
    assert instance.send_message.call_count == 2
