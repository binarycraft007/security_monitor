import pytest
from unittest.mock import MagicMock, patch
from security_monitor.security_utils import SecurityUtils


def test_get_secret_vault_fallback():
    # Mock hvac client
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    # Simulate Vault Error
    mock_client.secrets.kv.v2.read_secret_version.side_effect = Exception("Vault Down")

    with patch("hvac.Client", return_value=mock_client):
        # Init security in Vault mode
        sec = SecurityUtils(
            vault_url="http://fake:8200", vault_token="fake", local_mode=False
        )

        # Should return None and not crash
        val = sec.get_secret("secret/path", "key")
        assert val is None


def test_get_secret_vault_success():
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"key": "secret_value"}}
    }

    with patch("hvac.Client", return_value=mock_client):
        sec = SecurityUtils(
            vault_url="http://fake:8200", vault_token="fake", local_mode=False
        )
        val = sec.get_secret("secret/path", "key")
        assert val == "secret_value"
