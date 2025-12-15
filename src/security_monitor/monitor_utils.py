import asyncio
import functools
import inspect
import logging
import os
import smtplib
from email.mime.text import MIMEText
from typing import Any

import psutil
from ping3 import ping
from prometheus_client import Counter, Gauge, Summary, start_http_server

# Prometheus Metrics
REQUEST_TIME = Summary("request_processing_seconds", "Time spent processing request")
DB_QUERY_TIME = Summary("db_query_processing_seconds", "Time spent querying database")
CPU_USAGE = Gauge("system_cpu_usage_percent", "System CPU usage percent")
MEMORY_USAGE = Gauge("system_memory_usage_percent", "System Memory usage percent")
API_ERRORS = Counter("api_errors_total", "Total API errors")


class AlertManager:
    def __init__(self, email_config: dict | None = None):
        self.logger = logging.getLogger("AlertManager")
        self.email_config = email_config

        # Fallback to env vars if config not provided
        if not self.email_config:
            host = os.getenv("ALERT_SMTP_HOST")
            if host:
                self.email_config = {
                    "host": host,
                    "port": int(os.getenv("ALERT_SMTP_PORT", "25")),
                    "from": os.getenv("ALERT_FROM_EMAIL", "alert@example.com"),
                    "to": os.getenv("ALERT_TO_EMAIL", "admin@example.com"),
                }

    def check_threshold(self, metric_name: str, value: float, threshold: float):
        if value > threshold:
            msg = f"ALERT: {metric_name} is critical! Value: {value}, Threshold: {threshold}"
            self.logger.warning(msg)
            self.send_alert(f"Critical Alert: {metric_name}", msg)

    def send_alert(self, subject: str, body: str):
        if not self.email_config:
            return  # Email not configured

        try:
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self.email_config.get("from")  # type: ignore
            msg["To"] = self.email_config.get("to")  # type: ignore

            # Simple SMTP
            with smtplib.SMTP(
                self.email_config.get("host", "localhost"),  # type: ignore
                self.email_config.get("port", 25),  # type: ignore
            ) as s:
                s.send_message(msg)
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")


class MonitorUtils:
    def __init__(self, prometheus_port: int = 8000, email_config: dict | None = None):
        self.port = prometheus_port
        self._server_started = False
        self.logger = logging.getLogger("MonitorUtils")
        logging.basicConfig(level=logging.INFO)
        self.alert_manager = AlertManager(email_config)

    def start_metrics_server(self):
        if not self._server_started:
            try:
                start_http_server(self.port)
                self._server_started = True
                self.logger.info(
                    f"Prometheus metrics server started on port {self.port}"
                )
            except OSError:
                self.logger.warning(f"Port {self.port} likely already in use.")

    def collect_system_metrics(self):
        """
        Updates the Gauge metrics for CPU and Memory and checks alerts.
        """
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        CPU_USAGE.set(cpu)
        MEMORY_USAGE.set(mem)

        # Check alerts
        self.alert_manager.check_threshold("CPU", cpu, 80.0)
        self.alert_manager.check_threshold("Memory", mem, 90.0)

        return {"cpu": cpu, "memory": mem}

    def check_service_health(self, host: str, timeout: int = 1) -> bool:
        """
        Pings a host to check if it's alive.
        """
        try:
            r = ping(host, timeout=timeout)
            is_up = r is not None and r is not False
            return is_up
        except Exception as e:
            self.logger.error(f"Ping failed: {e}")
            return False

    def measure_execution_time(self, func):
        """
        Decorator to measure execution time of a function (Sync or Async).
        """
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                with REQUEST_TIME.time():
                    return await func(*args, **kwargs)

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                with REQUEST_TIME.time():
                    return func(*args, **kwargs)

            return sync_wrapper

    def record_error(self):
        API_ERRORS.inc()

    def db_query_timer(self):
        """
        Context manager for DB queries.
        Usage:
            with monitor.db_query_timer():
                db.execute(...)
        """
        return DB_QUERY_TIME.time()
