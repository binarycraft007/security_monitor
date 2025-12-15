# Security Monitor

A lightweight security and monitoring toolkit for Python applications, providing "Box-ready" security compliance and observability.

## Installation

```bash
uv add security-monitor
# or
pip install security-monitor
```

## Modules

### 1. Security Utils (Secrets & Encryption)

Integrates with HashiCorp Vault for secret management and provides AES encryption helper. Supports local encrypted storage for development.

```python
from security_monitor.security_utils import SecurityUtils, initialize_security, get_secret

# Initialize (Global)
# For Prod:
# initialize_security(vault_url='http://vault:8200', vault_token='my-token')
# For Local Dev (uses secrets.enc):
initialize_security(local_mode=True)

# Get Secret
# Looks up "db_creds" path and "password" key
db_pass = get_secret("db_creds:password")

# Encryption (AES)
sec = SecurityUtils(local_mode=True) 
encrypted_email = sec.encrypt_data("user@example.com")
email = sec.decrypt_data(encrypted_email)
```

**Local Secret Management:**

```python
# Create/Update local secrets
sec = SecurityUtils(local_mode=True)
sec.set_secret("db_creds", "password", "my_local_password")
```

### 2. Monitor Utils (Metrics, Health & Alerts)

Collects system metrics, exports to Prometheus, and alerts on critical thresholds.

```python
from security_monitor.monitor_utils import MonitorUtils

email_conf = {"host": "smtp.example.com", "to": "admin@example.com", "from": "mon@example.com"}
monitor = MonitorUtils(prometheus_port=8000, email_config=email_conf)

# Start Prometheus exporter
monitor.start_metrics_server()

# Collect System Metrics (CPU/Mem) & Check Alerts (CPU > 80%)
metrics = monitor.collect_system_metrics()

# Measure DB Query Time
with monitor.db_query_timer():
    # run_query()
    pass
```

### 3. Audit Logging

Immutable, structured logging with automatic sensitive data masking (Email, Phone).

```python
from security_monitor.audit_logs import AuditLogger

audit = AuditLogger(log_file="audit.jsonl", mask_sensitive=True)

# Log an event
audit.log_event(
    user="admin@example.com", # Will be masked
    action="update_user",
    result="success",
    details={"phone": "+1-555-0199"} # Will be masked
)
```

## Configuration

- **Vault:** Set `VAULT_ADDR` and `VAULT_TOKEN`.
- **Encryption:** Set `ENCRYPTION_KEY` (32 url-safe base64 bytes) for persistence.