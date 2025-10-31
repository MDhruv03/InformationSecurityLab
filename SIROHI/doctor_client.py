#!/usr/bin/env python3
"""
is_lab_complex_doctor_client.py

Doctor client for the privacy-preserving medical system.
- Generates its own ECDSA keypair for signing reports.
- Encrypts reports with AES-GCM, with the key wrapped
  by the Auditor's RSA public key.
- Encrypts department and expenses using the Server's
  Paillier public key.
"""
import os
import json
import socket
import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path
from phe import paillier

# --- Pycryptodome Imports ---
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# --- Cryptography Imports (for ECDSA) ---
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_to_der, decode_der_to_dss
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# --- Configuration ---
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5001
CLIENT_STATE_FILE = "doctor_state.json"
INPUT_DIR = "doctor_input_data"


# --- Utility Functions ---

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))


def load_client_state():
    if not os.path.exists(CLIENT_STATE_FILE):
        return {"doctor_id": None, "ecdsa_priv_pem": None, "server_keys": {}}
    with open(CLIENT_STATE_FILE, "r") as f:
        return json.load(f)


def save_client_state(state):
    with open(CLIENT_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def ensure_dirs():
    Path(INPUT_DIR).mkdir(exist_ok=True)
    file_path = Path(INPUT_DIR) / "sample_report.txt"
    if not file_path.exists():
        with file_path.open("w") as f:
            f.write("Patient: John Doe\nDiagnosis: Common Cold\n")
        print(f"Created {file_path}")


def send_request(action, body):
    """Send JSON request to server as 'doctor' and receive response."""
    req = {"action": action, "role": "doctor", "body": body}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((SERVER_HOST, SERVER_PORT))
            sock.sendall((json.dumps(req) + "\n").encode('utf-8'))
            data = sock.recv(4096).decode('utf-8')
            return json.loads(data)
    except Exception as e:
        return {"status": "error", "error": f"Connection failed: {e}"}


# --- Client-Side Crypto Functions ---

def get_ecdsa_key(state):
    """Load or generate a new ECDSA private key."""
    if state.get("ecdsa_priv_pem"):
        return serialization.load_pem_private_key(
            state["ecdsa_priv_pem"].encode('utf-8'),
            password=None
        )

    print("Generating new ECDSA (secp384r1) keypair for signing...")
    private_key = ec.generate_private_key(ec.SECP384R1())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    state["ecdsa_priv_pem"] = pem.decode('utf-8')
    save_client_state(state)
    print("New ECDSA key generated and saved to state.")
    return private_key


def fetch_server_keys(state):
    """Get server's public keys (Auditor RSA, Server Paillier)."""
    resp = send_request("get_public_info", {})
    if resp.get("status") == "ok":
        state["server_keys"] = resp
        save_client_state(state)
        print("[✅] Server public keys fetched and saved.")
        return True
    else:
        print(f"[❌] Failed to fetch server keys: {resp.get('error')}")
        return False


def register_doctor_client(state):
    if state.get("doctor_id"):
        print(f"Already registered as: {state['doctor_id']}")
        return

    doc_id = input("Enter new Doctor ID: ").strip()
    department = input("Enter Department (e.g., 'cardiology'): ").strip().lower()
    if not doc_id.isalnum() or not department:
        print("[❌] Invalid ID or department.")
        return

    if "paillier_pub_n" not in state.get("server_keys", {}):
        print("[❌] Must fetch server keys first (Option 2).")
        return

    # 1. Get/Generate ECDSA keys
    ecdsa_priv = get_ecdsa_key(state)
    ecdsa_pub_pem = ecdsa_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # 2. Encrypt department with Paillier
    try:
        paillier_pub = paillier.PaillierPublicKey(int(state["server_keys"]["paillier_pub_n"]))
        dept_hash = int.from_bytes(hashlib.sha256(department.encode()).digest(), 'big')
        enc_dept = paillier_pub.encrypt(dept_hash)

        # Serialize EncryptedNumber to JSON string
        enc_dept_b64 = b64e(json.dumps({
            'ciphertext': str(enc_dept.ciphertext()),
            'exponent': enc_dept.exponent
        }).encode('utf-8'))

    except Exception as e:
        print(f"[❌] Paillier encryption failed: {e}")
        return

    # 3. Send registration request
    body = {
        "doctor_id": doc_id,
        "ecdsa_pub_pem": ecdsa_pub_pem,
        "dept_paillier_b64": enc_dept_b64
    }
    resp = send_request("register_doctor", body)

    if resp.get("status") == "ok":
        state["doctor_id"] = doc_id
        save_client_state(state)
        print(f"[✅] Doctor '{doc_id}' registered successfully.")
    else:
        print(f"[❌] Registration failed: {resp.get('error')}")


def submit_report(state):
    if not state.get("doctor_id") or "auditor_rsa_pub_pem" not in state.get("server_keys", {}):
        print("[❌] Must be registered and have server keys first.")
        return

    # List files from input dir
    ensure_dirs()
    files = [f for f in os.listdir(INPUT_DIR) if f.endswith((".txt", ".md"))]
    if not files:
        print(f"[❌] No report files found in '{INPUT_DIR}' directory.")
        return

    print("Available reports to upload:")
    for i, f in enumerate(files): print(f"  {i + 1}. {f}")
    try:
        choice = int(input("Select file to upload: ")) - 1
        filename = files[choice]
        filepath = Path(INPUT_DIR) / filename
    except (IndexError, ValueError):
        print("[❌] Invalid selection.")
        return

    print(f"Processing '{filename}'...")
    report_bytes = filepath.read_bytes()
    report_hash = hashlib.sha256(report_bytes).digest()
    timestamp = datetime.now(timezone.utc).isoformat()

    # 1. Sign (hash + timestamp) with ECDSA
    ecdsa_priv = get_ecdsa_key(state)
    data_to_sign = report_hash + timestamp.encode('utf-8')
    signature = ecdsa_priv.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

    # 2. Generate one-time AES key
    aes_key = get_random_bytes(32)  # AES-256

    # 3. Encrypt report with AES-GCM
    nonce = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher_aes.encrypt_and_digest(report_bytes)

    # 4. Encrypt AES key with Auditor's RSA Public Key
    try:
        auditor_pub_key = RSA.import_key(state["server_keys"]["auditor_rsa_pub_pem"])
        cipher_rsa = PKCS1_OAEP.new(auditor_pub_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    except Exception as e:
        print(f"[❌] Failed to wrap AES key with Auditor's key: {e}")
        return

    # 5. Send blob to server
    body = {
        "doctor_id": state["doctor_id"],
        "filename": filename,
        "timestamp": timestamp,
        "encrypted_aes_key_b64": b64e(encrypted_aes_key),
        "aes_gcm_nonce_b64": b64e(nonce),
        "aes_gcm_tag_b64": b64e(tag),
        "aes_gcm_ciphertext_b64": b64e(ciphertext),
        "ecdsa_signature_b64": b64e(signature)
    }

    resp = send_request("upload_report", body)
    if resp.get("status") == "ok":
        print(f"[✅] Report '{filename}' securely uploaded (ID: {resp.get('report_id')}).")
        print("   (Server CANNOT read this report)")
    else:
        print(f"[❌] Report upload failed: {resp.get('error')}")


def submit_expense(state):
    if not state.get("doctor_id") or "paillier_pub_n" not in state.get("server_keys", {}):
        print("[❌] Must be registered and have server keys first.")
        return

    try:
        amount = int(input("Enter expense amount (integer): "))
        if amount < 0: raise ValueError
    except ValueError:
        print("[❌] Invalid amount.")
        return

    # Encrypt expense with Server's Paillier key
    try:
        paillier_pub = paillier.PaillierPublicKey(int(state["server_keys"]["paillier_pub_n"]))
        enc_exp = paillier_pub.encrypt(amount)

        # Serialize EncryptedNumber to JSON string
        enc_exp_b64 = b64e(json.dumps({
            'ciphertext': str(enc_exp.ciphertext()),
            'exponent': enc_exp.exponent
        }).encode('utf-8'))

    except Exception as e:
        print(f"[❌] Paillier encryption failed: {e}")
        return

    body = {
        "doctor_id": state["doctor_id"],
        "expense_paillier_b64": enc_exp_b64
    }

    resp = send_request("submit_expense", body)
    if resp.get("status") == "ok":
        print(f"[✅] Encrypted expense ({amount}) submitted successfully.")
    else:
        print(f"[❌] Expense submission failed: {resp.get('error')}")


# --- Main Menu ---

def main():
    state = load_client_state()

    while True:
        print("\n--- Doctor Client Menu ---")
        doc_id = state.get("doctor_id")
        keys = "✅" if state.get("server_keys") else "❌"
        print(f"Logged In: {doc_id} | Server Keys: {keys}")
        print("1. Register as New Doctor")
        print("2. Fetch Server Public Keys")
        print("3. Submit Medical Report")
        print("4. Submit Expense")
        print("0. Exit")

        choice = input("Choice: ").strip()

        if choice == "1":
            register_doctor_client(state)
        elif choice == "2":
            fetch_server_keys(state)
        elif choice == "3":
            submit_report(state)
        elif choice == "4":
            submit_expense(state)
        elif choice == "0":
            print("Exiting.")
            break
        else:
            print("[❌] Invalid choice.")


if __name__ == "__main__":
    main()