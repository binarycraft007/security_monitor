# PRD 2: General Security & Monitoring Toolset (Module 2)

**Version:** 1.0
**Status:** Draft
**Language:** Python

## 1. Executive Summary
This module provides a lightweight, reusable "plug-and-play" component for Python projects to address common security and observability gaps. It integrates sensitive data management, encryption, performance monitoring, and audit logging into a single library that can be integrated into any project with minimal code changes (≤ 5 lines).

## 2. Objectives
*   **Security:** Eliminate hardcoded secrets and ensure encryption of sensitive data at rest and in transit.
*   **Observability:** Provide transparent runtime status (CPU, API latency) and structured logs.
*   **Compliance:** Create immutable audit trails for all critical operations.
*   **Ease of Use:** "Out of the box" functionality to reduce compliance costs.

## 3. Scope of Work

### 3.1 Functional Requirements

#### 3.1.1 Sensitive Information Management
*   **Storage Strategy:**
    *   **Production:** Integration with **HashiCorp Vault**.
    *   **Local Development:** Simplified encrypted file storage.
*   **Access Pattern:** Secrets must be retrieved via key names (e.g., `get_secret("db_password")`).
*   **Rotation:** Support automatic secret rotation.
*   **Constraint:** Absolutely **NO** plaintext hardcoding of database passwords or API keys in the source code.

#### 3.1.2 Data Encryption
*   **Data in Transit:** Enforce HTTPS for API requests.
*   **Data at Rest:**
    *   Encrypt sensitive fields (e.g., Mobile Numbers, Emails) using **AES**.
    *   Encryption keys must be stored in Vault.
    *   Support automatic decryption upon query.

#### 3.1.3 Performance Monitoring
*   **Metrics Collection:** Real-time collection of:
    *   API Response Time (Latency)
    *   CPU Usage
    *   Memory Usage
    *   Database Query Duration
    *   Request Volume / Error Rates
*   **Format:** Export metrics in **Prometheus** format for integration with Grafana.
*   **Service Health:** Basic "Ping" or heartbeat detection.

#### 3.1.4 Audit Logging
*   **Scope:** Record all critical operations (Login, Data Modification, File Download).
*   **Data Structure (JSONL):**
    *   Timestamp
    *   User ID
    *   Operation Content/Type
    *   Result/Status
*   **Immutability:** Logs must be append-only. Modification or deletion of logs is prohibited.
*   **Search:** Logs must be queryable by User, Time, or Operation Type.

### 3.2 Deliverables (Output)
1.  **`security_utils.py`:** A library containing functions for Encryption/Decryption and Vault connection management.
2.  **`monitor_utils.py`:** A script/library for metric collection and service health checks.
3.  **`audit_logs.jsonl`:** The structured log file output.

## 4. Technical Requirements

### 4.1 Technology Stack
*   **Language:** Python
*   **Secret Management:** `hashicorp-vault`
*   **Encryption:** `cryptography`, `pyjwt` (for Identity/Auth)
*   **Monitoring:** `prometheus-client`, `ping3`
*   **Logging:** Standard Python `logging` (configured for structured output).

### 4.2 Integration Standards
*   **Code Impact:** Integration into an existing project should require wrapper functions or decorators, modifying **≤ 5 lines** of the host project's code.
*   **Coverage:** Monitoring must cover at least 5 core metrics (e.g., API latency, Error Rate, CPU, etc.).

## 5. Advanced Features (Nice-to-Have)
*   **Alerting:** Trigger email notifications if abnormal metrics occur (e.g., CPU > 80%).
*   **Log Masking:** Automatically detect and mask sensitive info (IDs, Phone Numbers) in logs before writing to disk.

## 6. Constraints & Anti-Patterns
*   **Hardcoding:** Hardcoding secrets (even in comments) results in immediate failure/deduction.
*   **Unstructured Logs:** Logs must be machine-readable (JSON/JSONL), not plain text strings.
*   **Weak Encryption:** Use of Base64 or other reversible encoding schemes as "encryption" is prohibited.
