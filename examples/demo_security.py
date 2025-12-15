import os

from cryptography.fernet import Fernet

# Import everything from the top level module now
from security_monitor.security_utils import (
    decrypt_data,
    encrypt_data,
    generate_token,
    get_secret,
    initialize_security,
    set_secret,
    verify_token,
)

# 0. Setup Environment (Ensure consistent key for demo)
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()

# 1. Initialize in Local Mode (for development)
print("[Init] Initializing Security (Local Mode)...")
initialize_security(local_mode=True, local_secret_file="my_secrets.enc")

# 2. Secret Management
print("\n[Secrets] Setting and Getting Secrets...")
# Now we use the clean global function
set_secret("database", "password", "SuperSecretPassword123!")

# Get the secret
db_pass = get_secret("database:password")
print(f" -> Retrieved Database Password: {db_pass}")

# 3. Data Encryption (AES)
print("\n[Encryption] Encrypting Sensitive Data...")
email = "user@example.com"
encrypted = encrypt_data(email)
print(f" -> Original: {email}")
print(f" -> Encrypted: {encrypted}")

decrypted = decrypt_data(encrypted)
print(f" -> Decrypted: {decrypted}")

# 4. JWT Tokens
print("\n[JWT] Generating Authentication Token...")
user_data = {"user_id": 101, "role": "admin"}
token = generate_token(user_data, expiry_minutes=30)
print(f" -> Token: {token}")

# Verify
decoded = verify_token(token)
print(f" -> Verified Payload: {decoded}")

