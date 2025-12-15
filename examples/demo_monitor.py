import random
import time

from security_monitor.audit_logs import AuditLogger
from security_monitor.monitor_utils import MonitorUtils

# 1. Setup Monitor
# In a real app, email_config would be real SMTP settings
monitor = MonitorUtils(prometheus_port=8000)

print("[Monitor] Starting Prometheus Metrics Server on port 8000...")
monitor.start_metrics_server()

# 2. Setup Audit Logger
audit = AuditLogger("audit_logs.jsonl", mask_sensitive=True)

print("[Monitor] Simulating application activity (Ctrl+C to stop)...")

try:
    for i in range(5):
        print(f"\n--- Iteration {i+1} ---")

        # A. Collect System Metrics
        metrics = monitor.collect_system_metrics()
        print(f" -> System Metrics: CPU {metrics['cpu']}%  Mem {metrics['memory']}%")

        # B. Simulate DB Query
        with monitor.db_query_timer():
            # Simulate work
            time.sleep(random.uniform(0.1, 0.3))
        print(" -> DB Query executed (timed).")

        # C. Log Audit Event
        user_email = f"user{i}@example.com"
        audit.log_event(
            user=user_email,
            action="data_export",
            result="success",
            details={"phone_number": "+1-555-0123", "record_id": i},
        )
        print(f" -> Logged audit event for {user_email}")

        # D. Query Logs
        logs = audit.query_logs(action="data_export")
        last_log = logs[-1]
        print(
            f" -> Verify Log Masking: User='{last_log['user']}', Phone='{last_log['details']['phone_number']}'"
        )

        time.sleep(1)

except KeyboardInterrupt:
    print("\nStopping...")

print("\nDone. Check 'audit_trail.jsonl' for logs.")
