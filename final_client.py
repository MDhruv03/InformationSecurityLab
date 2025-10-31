"""
client.py - Doctor client.

UPDATED: contains many placeholders and commented functions for quick swapping:
 - alternative asymmetric (ElGamal) wrap
 - alternative signing (RSA sign / Schnorr sketch)
 - optional hashing-of-ciphertext steps
 - AES-CBC placeholder
 - Diffie-Hellman handshake skeleton

Instructions: search for "### UNCOMMENT TO USE" to reveal toggles.
"""
import os
import json
import socket
import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes as ch_hashes
from cryptography.hazmat.primitives.asymmetric import ec as ch_ec
from cryptography.hazmat.primitives import serialization as ch_serialization
from phe import paillier

# ---------- CONFIG ----------
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5001
CLIENT_STATE_FILE = "doctor_state.json"
INPUT_DIR = "doctor_input_data"
CONN_TIMEOUT = 2.0  # secs

# ---------- UTILS ----------
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
            f.write("Patient: John Doe\nDiagnosis: Common Cold\nRecommendations: Rest & fluids.\n")
        print(f"[client] Created sample report at {file_path}")

# ---------- NETWORK ----------
def check_server_up(host, port, timeout=CONN_TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def send_request(action, body):
    req = {"action": action, "role": "doctor", "body": body}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((SERVER_HOST, SERVER_PORT))
            sock.sendall((json.dumps(req) + "\n").encode('utf-8'))
            data = sock.recv(8192).decode('utf-8')
            return json.loads(data)
    except Exception as e:
        return {"status": "error", "error": f"Connection failed: {e}"}

# ---------- CRYPTO HELPERS ----------
def get_ecdsa_key(state):
    if state.get("ecdsa_priv_pem"):
        return ch_serialization.load_pem_private_key(state["ecdsa_priv_pem"].encode('utf-8'), password=None)
    print("[client] Generating new ECDSA (secp384r1) keypair...")
    private_key = ch_ec.generate_private_key(ch_ec.SECP384R1())
    pem = private_key.private_bytes(
        encoding=ch_serialization.Encoding.PEM,
        format=ch_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=ch_serialization.NoEncryption()
    )
    state["ecdsa_priv_pem"] = pem.decode('utf-8')
    save_client_state(state)
    print("[client] New ECDSA key generated and saved.")
    return private_key

# ---------- CLIENT ACTIONS ----------
def fetch_server_keys(state):
    resp = send_request("get_public_info", {})
    if resp.get("status") == "ok":
        state["server_keys"] = resp
        save_client_state(state)
        print("[client] Server public keys fetched and saved.")
        return True
    else:
        print(f"[client] Failed to fetch server keys: {resp.get('error')}")
        return False

def register_doctor_client(state):
    if state.get("doctor_id"):
        print(f"[client] Already registered as: {state['doctor_id']}")
        return
    doc_id = input("Enter new Doctor ID: ").strip()
    department = input("Enter Department (e.g., 'cardiology'): ").strip().lower()
    if not doc_id.isalnum() or not department:
        print("[client] Invalid ID or department.")
        return
    if "paillier_pub_n" not in state.get("server_keys", {}):
        print("[client] Must fetch server keys first (Option 2).")
        return
    ecdsa_priv = get_ecdsa_key(state)
    ecdsa_pub_pem = ecdsa_priv.public_key().public_bytes(
        encoding=ch_serialization.Encoding.PEM,
        format=ch_serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    try:
        paillier_pub = paillier.PaillierPublicKey(int(state["server_keys"]["paillier_pub_n"]))
        dept_hash = int.from_bytes(hashlib.sha256(department.encode()).digest(), 'big')
        enc_dept = paillier_pub.encrypt(dept_hash)
        enc_dept_b64 = b64e(json.dumps({
            'ciphertext': str(enc_dept.ciphertext()),
            'exponent': enc_dept.exponent
        }).encode('utf-8'))
    except Exception as e:
        print(f"[client] Paillier encryption failed: {e}")
        return
    body = {
        "doctor_id": doc_id,
        "ecdsa_pub_pem": ecdsa_pub_pem,
        "dept_paillier_b64": enc_dept_b64
    }
    resp = send_request("register_doctor", body)
    if resp.get("status") == "ok":
        state["doctor_id"] = doc_id
        save_client_state(state)
        print(f"[client] Doctor '{doc_id}' registered successfully.")
    else:
        print(f"[client] Registration failed: {resp.get('error')}")

def submit_report(state):
    if not state.get("doctor_id") or "auditor_rsa_pub_pem" not in state.get("server_keys", {}):
        print("[client] Must be registered and have server keys first.")
        return
    ensure_dirs()
    files = [f for f in os.listdir(INPUT_DIR) if f.endswith((".txt", ".md"))]
    if not files:
        print(f"[client] No report files found in '{INPUT_DIR}'")
        return
    print("Available reports:")
    for i, f in enumerate(files): print(f"  {i + 1}. {f}")
    try:
        choice = int(input("Select file to upload: ")) - 1
        filename = files[choice]
        filepath = Path(INPUT_DIR) / filename
    except (IndexError, ValueError):
        print("[client] Invalid selection.")
        return
    report_bytes = filepath.read_bytes()
    report_hash = hashlib.sha256(report_bytes).digest()
    timestamp = datetime.now(timezone.utc).isoformat()

    # SIGN: default ECDSA
    ecdsa_priv = get_ecdsa_key(state)
    data_to_sign = report_hash + timestamp.encode('utf-8')
    signature = ecdsa_priv.sign(data_to_sign, ch_ec.ECDSA(ch_hashes.SHA256()))

    # SYMMETRIC: AES-GCM default
    aes_key = get_random_bytes(32)  # AES-256
    nonce = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher_aes.encrypt_and_digest(report_bytes)

    # OPTIONAL HASH OF CIPHERTEXT (comment/uncomment to enable)
    # ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()  # store or sign if needed

    # ASYMMETRIC WRAP: default RSA wrap using auditor public key
    try:
        auditor_pub_key = RSA.import_key(state["server_keys"]["auditor_rsa_pub_pem"])
        cipher_rsa = PKCS1_OAEP.new(auditor_pub_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    except Exception as e:
        print(f"[client] Failed to wrap AES key with Auditor's key: {e}")
        return

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
        print(f"[client] Report '{filename}' securely uploaded (ID: {resp.get('report_id')}).")
    else:
        print(f"[client] Report upload failed: {resp.get('error')}")

def submit_expense(state):
    if not state.get("doctor_id") or "paillier_pub_n" not in state.get("server_keys", {}):
        print("[client] Must be registered and have server keys first.")
        return
    try:
        amount = int(input("Enter expense amount (integer): "))
        if amount < 0:
            raise ValueError
    except ValueError:
        print("[client] Invalid amount.")
        return
    try:
        paillier_pub = paillier.PaillierPublicKey(int(state["server_keys"]["paillier_pub_n"]))
        enc_exp = paillier_pub.encrypt(amount)
        enc_exp_b64 = b64e(json.dumps({
            'ciphertext': str(enc_exp.ciphertext()),
            'exponent': enc_exp.exponent
        }).encode('utf-8'))
    except Exception as e:
        print(f"[client] Paillier encryption failed: {e}")
        return
    body = {"doctor_id": state["doctor_id"], "expense_paillier_b64": enc_exp_b64}
    resp = send_request("submit_expense", body)
    if resp.get("status") == "ok":
        print(f"[client] Encrypted expense submitted.")
    else:
        print(f"[client] Expense submission failed: {resp.get('error')}")

# ---------- PLACEHOLDER SECTIONS (UNCOMMENT AS NEEDED) ----------
# Find markers like "### UNCOMMENT TO USE ..." to switch behaviour quickly.

### PLACEHOLDER: RSA SIGN (as alternative to ECDSA)
"""
### UNCOMMENT TO USE RSA SIGNING
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
def rsa_sign(privkey_pem: bytes, message: bytes) -> bytes:
    priv = RSA.import_key(privkey_pem)
    h = SHA256.new(message)
    sig = pkcs1_15.new(priv).sign(h)
    return sig
def rsa_verify(pubkey_pem: bytes, signature: bytes, message: bytes) -> bool:
    pub = RSA.import_key(pubkey_pem)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(pub).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
# To use: replace ECDSA sign call above with rsa_sign(state['rsa_priv_pem'], data_to_sign)
"""

### PLACEHOLDER: ElGamal asymmetric wrap (client side skeleton)
"""
### UNCOMMENT TO USE ELGAMAL WRAP (client-side skeleton)
from Crypto.PublicKey import ElGamal
def elgamal_wrap_aes_key(pubkey_elgamal_pem: bytes, aes_key: bytes):
    # PyCryptodome's ElGamal usage differs; this is a skeleton. Use a library or
    # implement proper math for exam. Return {'c1': int, 'c2': int} or bytes.
    raise NotImplementedError("ElGamal wrap skeleton")
"""

### PLACEHOLDER: Hash AES ciphertext before signing (common exam requirement)
"""
### UNCOMMENT to SIGN the HASH of ciphertext instead of plaintext-hash
ciphertext_hash = hashlib.sha256(ciphertext).digest()
data_to_sign = ciphertext_hash + timestamp.encode('utf-8')
signature = ecdsa_priv.sign(data_to_sign, ch_ec.ECDSA(ch_hashes.SHA256()))
# Server must then verify using same method.
"""

### PLACEHOLDER: AES-CBC alternate (client)
"""
### UNCOMMENT to use AES-CBC (instead of GCM)
from Crypto.Util.Padding import pad
aes_key = get_random_bytes(32)
iv = get_random_bytes(16)
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(report_bytes, AES.block_size))
# You'll need to send iv and used padding info. Note: CBC has no auth tag by default.
"""

### PLACEHOLDER: Schnorr signature skeleton (educational)
"""
### UNCOMMENT to use SCHNORR sketch (non-standard code; implement math for exam)
def schnorr_sign(sk_int, message_bytes, params):
    # params: {'p':..., 'q':..., 'g':...}
    # Return signature tuple (r, s) bytes or serialized form
    raise NotImplementedError("Schnorr skeleton - implement per definition")
"""

### PLACEHOLDER: Diffie-Hellman handshake skeleton (client-side)
"""
### UNCOMMENT to perform a DH key-exchange prior to symmetric encryption
def dh_client_handshake(server_pub_int, g, p):
    # client generates priv a, pub A = g^a mod p, compute shared = server_pub^a mod p
    raise NotImplementedError("DH handshake skeleton; ensure server performs matching flow")
"""

# ---------- MAIN ----------
def main():
    print("[client] Checking server availability...")
    if not check_server_up(SERVER_HOST, SERVER_PORT):
        print(f"[client] ERROR: Cannot reach server at {SERVER_HOST}:{SERVER_PORT}. Start server first.")
        return
    print("[client] Server reachable. Continuing.")

    state = load_client_state()
    while True:
        doc_id = state.get("doctor_id")
        keys_flag = "✅" if state.get("server_keys") else "❌"
        print("\n--- Doctor Client Menu ---")
        print(f"Logged In: {doc_id} | Server Keys: {keys_flag}")
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
            print("[client] Exiting.")
            break
        else:
            print("[client] Invalid choice.")

if __name__ == "__main__":
    main()
