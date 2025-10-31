"""
merged_client.py
Flexible client that can pick algorithms (top-level prefs) and send JSON payloads.
It attaches explicit alg_* fields so server can interpret.

Usage:
    python merged_client.py

Client refuses to run if server not reachable (you asked client should not start when server is down).
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
from Crypto.Util.number import bytes_to_long, long_to_bytes
from phe import paillier

# ECC (ECIES style)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as ch_hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization as ch_serialization
from cryptography.hazmat.primitives.asymmetric import ec as ch_ec
from cryptography.hazmat.primitives import hashes

# ---------- CONFIG / PREFERENCES ----------
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5001
CLIENT_STATE_FILE = "client_state.json"
INPUT_DIR = "input_reports"
CONN_TIMEOUT = 2.0

# Default preferences: you can edit here or via menu in runtime
PREFS = {
    "alg_report_enc": "AES-GCM",   # "AES-GCM" or "AES-CBC"
    "alg_key_enc": "RSA",          # "RSA" | "ElGamal" | "ECC"
    "alg_sig": "ECDSA",            # "ECDSA" | "RSA" | "ElGamal"
    "alg_dept_enc": "Paillier",    # "Paillier" or "SSE"
    "alg_expense_he": "Paillier"
}

# ---------- UTIL ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')
def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

def load_state():
    if not os.path.exists(CLIENT_STATE_FILE):
        return {"doctor_id": None, "keys": {}, "server_keys": {}, "prefs": PREFS.copy()}
    with open(CLIENT_STATE_FILE, "r") as f:
        return json.load(f)
def save_state(s):
    with open(CLIENT_STATE_FILE, "w") as f:
        json.dump(s, f, indent=2)

def ensure_dirs():
    Path(INPUT_DIR).mkdir(exist_ok=True)
    sample = Path(INPUT_DIR) / "sample.txt"
    if not sample.exists():
        sample.write_text("Sample patient report\nDiagnosis: none\n")

# ---------- NETWORK ----------
def check_server_up(host, port, timeout=CONN_TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def send_request(action, role, body):
    req = {"action": action, "role": role, "body": body}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall((json.dumps(req) + "\n").encode('utf-8'))
            data = s.recv(65536).decode('utf-8')
            return json.loads(data)
    except Exception as e:
        return {"status":"error","error":str(e)}

# ---------- CRYPTO HELPERS ----------
# ECDSA (using cryptography) key generation & sign
def ensure_ecdsa(state):
    if state["keys"].get("ecdsa_priv_pem"):
        return ch_serialization.load_pem_private_key(state["keys"]["ecdsa_priv_pem"].encode(), password=None)
    priv = ch_ec.generate_private_key(ch_ec.SECP384R1())
    pem = priv.private_bytes(
        encoding=ch_serialization.Encoding.PEM,
        format=ch_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=ch_serialization.NoEncryption()
    ).decode()
    state["keys"]["ecdsa_priv_pem"] = pem
    state["keys"]["ecdsa_pub_pem"] = priv.public_key().public_bytes(
        ch_serialization.Encoding.PEM, ch_serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    save_state(state)
    return priv

# ElGamal wrap (client side): client should send ElGamal pub params or use server pub if provided
def elgamal_encrypt_bytes(pub_params: dict, aes_key: bytes) -> dict:
    """
    pub_params: dict with 'p','g','y' (integers)
    returns {c1: str, c2: str}
    """
    p = int(pub_params["p"]); g = int(pub_params["g"]); y = int(pub_params["y"])
    m = bytes_to_long(aes_key)
    # choose random k
    k = int.from_bytes(get_random_bytes(32), "big") % (p-2) + 1
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return {"c1": str(c1), "c2": str(c2)}

# ECC ECIES-style encrypt AES key
def ecc_encrypt_aeskey(pub_pem: str, aes_key: bytes) -> dict:
    peer_pub = ch_serialization.load_pem_public_key(pub_pem.encode())
    eph = ch_ec.generate_private_key(ch_ec.SECP256R1())
    shared = eph.exchange(ec.ECDH(), peer_pub)
    derived = HKDF(algorithm=ch_hashes.SHA256(), length=32, salt=None, info=b"ecies").derive(shared)
    nonce = get_random_bytes(12)
    cipher = Cipher(algorithms.AES(derived), modes.GCM(nonce))
    enc = cipher.encryptor()
    ct = enc.update(aes_key) + enc.finalize()
    tag = enc.tag
    eph_pub_pem = eph.public_key().public_bytes(ch_serialization.Encoding.PEM, ch_serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return {"ephemeral_pub": eph_pub_pem, "nonce": b64e(nonce), "ct": b64e(ct), "tag": b64e(tag)}

# ---------- HIGH-LEVEL ACTIONS ----------
def fetch_server_keys(state):
    resp = send_request("get_public_info", "doctor", {})
    if resp.get("status") == "ok":
        # server returns auditor_rsa_pub_pem and paillier_pub_n
        state["server_keys"] = resp
        save_state(state)
        print("[client] fetched server keys.")
        return True
    else:
        print("[client] fetch failed:", resp.get("error"))
        return False

def register_doctor(state):
    if state.get("doctor_id"):
        print("[client] already registered:", state["doctor_id"])
        return
    doc_id = input("Doctor ID (alnum): ").strip()
    if not doc_id.isalnum():
        print("invalid id")
        return
    # set up sig pub depending on preference
    prefs = state.get("prefs", PREFS)
    sig_alg = prefs.get("alg_sig", "ECDSA")
    sig_pub = {}
    if sig_alg == "ECDSA":
        priv = ensure_ecdsa(state)
        sig_pub["ecdsa_pub_pem"] = state["keys"]["ecdsa_pub_pem"]
    elif sig_alg == "RSA":
        rsa = RSA.generate(2048)
        state["keys"]["rsa_priv_pem"] = rsa.export_key().decode()
        state["keys"]["rsa_pub_pem"] = rsa.publickey().export_key().decode()
        sig_pub["rsa_pub_pem"] = state["keys"]["rsa_pub_pem"]
    elif sig_alg == "ElGamal":
        # client generates small ElGamal keypair and sends pub params
        # NOTE: requires pycryptodome ElGamal available; here we create params manually
        # For exams you can paste generated params into state["keys"]["elgamal_priv"] and ["elgamal_pub"]
        from Crypto.PublicKey import ElGamal
        from Crypto import Random
        key = ElGamal.generate(512, Random.new().read)
        priv = {"p": int(key.p), "g": int(key.g), "x": int(key.x)}
        pub = {"p": int(key.p), "g": int(key.g), "y": int(key.y)}
        state["keys"]["elgamal_priv"] = priv
        state["keys"]["elgamal_pub"] = pub
        sig_pub["elgamal_pub"] = pub
    else:
        print("unknown sig alg")
        return

    # dept encryption (Paillier expected)
    prefs = state.get("prefs", PREFS)
    alg_dept = prefs.get("alg_dept_enc", "Paillier")
    dept = input("Department (keyword): ").strip().lower()
    if alg_dept == "Paillier":
        if not state.get("server_keys") or "paillier_pub_n" not in state["server_keys"]:
            print("fetch server keys first")
            return
        pub_n = state["server_keys"]["paillier_pub_n"]
        pub = paillier.PaillierPublicKey(int(pub_n))
        dept_hash = int.from_bytes(hashlib.sha256(dept.encode()).digest(), "big")
        enc = pub.encrypt(dept_hash)
        dept_payload = {"ciphertext": int(enc.ciphertext()), "exponent": enc.exponent}
    else:
        # SSE or plaintext fallback
        dept_payload = {"plain": dept}

    body = {"doctor_id": doc_id, "sig_pub": sig_pub, "alg_dept_enc": alg_dept, "dept_payload": dept_payload}
    resp = send_request("register_doctor", "doctor", body)
    if resp.get("status") == "ok":
        state["doctor_id"] = doc_id
        save_state(state)
        print("registered")
    else:
        print("register failed:", resp.get("error"))

def submit_report(state):
    if not state.get("doctor_id"):
        print("register first")
        return
    ensure_dirs()
    files = [f for f in os.listdir(INPUT_DIR) if f.lower().endswith((".txt", ".md"))]
    if not files:
        print("no files in", INPUT_DIR)
        return
    for i,f in enumerate(files): print(f"{i+1}. {f}")
    idx = int(input("choose file #: ").strip()) - 1
    filename = files[idx]
    path = Path(INPUT_DIR) / filename
    report_bytes = path.read_bytes()
    timestamp = datetime.utcnow().isoformat()
    prefs = state.get("prefs", PREFS)

    # sign
    sig_payload = {}
    if prefs["alg_sig"] == "ECDSA":
        priv = ensure_ecdsa(state)
        data = hashlib.sha256(report_bytes).digest() + timestamp.encode()
        sig = priv.sign(data, ch_ec.ECDSA(ch_hashes.SHA256()))
        sig_payload = {"alg":"ECDSA", "sig_b64": b64e(sig)}
    elif prefs["alg_sig"] == "RSA":
        priv_pem = state["keys"]["rsa_priv_pem"]
        priv = RSA.import_key(priv_pem.encode())
        from Crypto.Signature import pkcs1_15
        from Crypto.Hash import SHA256
        h = SHA256.new(hashlib.sha256(report_bytes).digest() + timestamp.encode())
        sig = pkcs1_15.new(priv).sign(h)
        sig_payload = {"alg":"RSA", "sig_b64": b64e(sig)}
    elif prefs["alg_sig"] == "ElGamal":
        # simplified: send an MD5-based r,s. Client must ensure server verifies same way.
        from Crypto.Hash import MD5
        from Crypto.Util.number import inverse
        # using state["keys"]["elgamal_priv"]
        priv = state["keys"].get("elgamal_priv")
        pub = state["keys"].get("elgamal_pub")
        if not priv or not pub:
            print("no elgamal keys; register using ElGamal signature option")
            return
        p = int(pub["p"]); g = int(pub["g"]); x = int(priv["x"])
        H = int.from_bytes(hashlib.md5(report_bytes + timestamp.encode()).digest(), "big") % (p-1)
        # choose k with gcd(k,p-1)==1
        k = int.from_bytes(get_random_bytes(32), "big") % (p-2) + 2
        while hashlib.gcd(k, p-1) != 1:
            k = int.from_bytes(get_random_bytes(32), "big") % (p-2) + 2
        r = pow(g, k, p)
        kinv = pow(k, -1, p-1)
        s = (kinv * (H - x * r)) % (p-1)
        sig_payload = {"r": str(r), "s": str(s)}

    # symmetric encrypt report with AES-GCM or AES-CBC
    aes_key = get_random_bytes(32)  # AES-256
    enc_report = {}
    if prefs["alg_report_enc"] == "AES-GCM":
        nonce = get_random_bytes(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(report_bytes)
        enc_report = {"mode":"GCM","nonce": b64e(nonce), "ct": b64e(ct), "tag": b64e(tag)}
    else:
        iv = get_random_bytes(16)
        from Crypto.Util.Padding import pad
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(report_bytes, AES.block_size))
        enc_report = {"mode":"CBC","iv": b64e(iv), "ct": b64e(ct)}

    # key transport according to alg_key_enc
    kt = {}
    if prefs["alg_key_enc"] == "RSA":
        if "auditor_rsa_pub_pem" not in state.get("server_keys", {}):
            print("fetch server keys first")
            return
        pub_pem = state["server_keys"]["auditor_rsa_pub_pem"]
        rsa_pub = RSA.import_key(pub_pem.encode())
        enc_key = PKCS1_OAEP.new(rsa_pub).encrypt(aes_key)
        kt = {"enc_key_b64": b64e(enc_key)}
    elif prefs["alg_key_enc"] == "ElGamal":
        # server must advertise ElGamal pub params in server_keys for this to work
        if "elgamal_pub" not in state.get("server_keys", {}):
            print("server elgamal pub missing")
            return
        kt = elgamal_encrypt_bytes(state["server_keys"]["elgamal_pub"], aes_key)
    elif prefs["alg_key_enc"] == "ECC":
        if "ecc_pub_pem" not in state.get("server_keys", {}):
            print("server ecc pub missing")
            return
        enc = ecc_encrypt_aeskey(state["server_keys"]["ecc_pub_pem"], aes_key)
        kt = {"ecc_ephemeral": enc["ephemeral_pub"], "ecc_nonce": enc["nonce"], "ecc_ct": enc["ct"], "ecc_tag": enc["tag"]}
    else:
        print("unknown key transport")
        return

    body = {
        "doctor_id": state["doctor_id"],
        "filename": filename,
        "timestamp": timestamp,
        "alg_report_enc": prefs["alg_report_enc"],
        "enc_report": enc_report,
        "alg_key_enc": prefs["alg_key_enc"],
        "key_transport": kt,
        "sig": sig_payload
    }
    resp = send_request("upload_report", "doctor", body)
    print("server response:", resp)

def submit_expense(state):
    if not state.get("doctor_id"):
        print("register first")
        return
    prefs = state.get("prefs", PREFS)
    amt = int(input("Amount integer: ").strip())
    if prefs["alg_expense_he"] == "Paillier":
        if "paillier_pub_n" not in state.get("server_keys", {}):
            print("fetch server keys")
            return
        pub_n = state["server_keys"]["paillier_pub_n"]
        pub = paillier.PaillierPublicKey(int(pub_n))
        c = pub.encrypt(amt)
        payload = {"ciphertext": int(c.ciphertext()), "exponent": c.exponent}
        body = {"doctor_id": state["doctor_id"], "alg_expense_he":"Paillier", "cipher": payload}
    else:
        print("only Paillier implemented for expenses in this client; extend as needed.")
        return
    resp = send_request("submit_expense", "doctor", body)
    print("server:", resp)

# ---------- MAIN ----------
def main():
    if not check_server_up(SERVER_HOST, SERVER_PORT):
        print("[client] server not reachable; client will not start. Start server first.")
        return
    state = load_state()
    while True:
        print("\n--- Client Menu ---")
        print("1) Fetch server keys")
        print("2) Register doctor")
        print("3) Submit report")
        print("4) Submit expense")
        print("5) Preferences (current):", state.get("prefs", PREFS))
        print("0) Exit")
        c = input("Choice: ").strip()
        if c == "1":
            fetch_server_keys(state)
        elif c == "2":
            register_doctor(state)
        elif c == "3":
            submit_report(state)
        elif c == "4":
            submit_expense(state)
        elif c == "5":
            # quick prefs editor
            p = state.get("prefs", PREFS)
            for k in p:
                v = input(f"{k} [{p[k]}]: ").strip()
                if v: p[k] = v
            state["prefs"] = p
            save_state(state)
        elif c == "0":
            break
        else:
            print("invalid")

if __name__ == "__main__":
    main()
