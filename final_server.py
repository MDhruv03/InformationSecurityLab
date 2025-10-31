"""
server.py - Server + integrated Auditor console.

UPDATED: Contains many commented placeholder functions and alternate crypto
implementations. To use an alternative, find the marker lines containing:
    ### UNCOMMENT TO USE <FEATURE> ###
and follow the inline note.

Run:
    python server.py
"""
import os
import json
import threading
import socketserver
import base64
import time
import hashlib
from pathlib import Path

# Core crypto libs used by default
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from phe import paillier

# For ECDSA verification when auditing
from cryptography.hazmat.primitives import hashes as ch_hashes
from cryptography.hazmat.primitives.asymmetric import ec as ch_ec
from cryptography.hazmat.primitives import serialization as ch_serialization
from cryptography.exceptions import InvalidSignature as ChInvalidSignature

# ---------- CONFIG ----------
DATA_DIR = "server_data"
DOCTORS_FILE = os.path.join(DATA_DIR, "doctors_db.json")
EXPENSES_FILE = os.path.join(DATA_DIR, "expenses_db.json")
REPORTS_FILE = os.path.join(DATA_DIR, "reports_db.json")
PAILLIER_PRIV_FILE = os.path.join(DATA_DIR, "paillier.key")
PAILLIER_PUB_FILE = os.path.join(DATA_DIR, "paillier.pub")
AUDITOR_RSA_PRIV_FILE = os.path.join(DATA_DIR, "auditor_rsa_key.pem")
AUDITOR_RSA_PUB_FILE = os.path.join(DATA_DIR, "auditor_rsa_key.pub")
HOST = "127.0.0.1"
PORT = 5001
lock = threading.Lock()

# ---------- UTILS ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

def read_json_db(path, default):
    with lock:
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return default

def write_json_db(path, data):
    with lock:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)

# ---------- KEY INIT (Pluggable) ----------
def init_keys():
    os.makedirs(DATA_DIR, exist_ok=True)

    # Auditor RSA (default)
    if not os.path.exists(AUDITOR_RSA_PRIV_FILE):
        key = RSA.generate(2048)
        with open(AUDITOR_RSA_PRIV_FILE, "wb") as f:
            # demo passphrase; in exam you may remove
            f.write(key.export_key(passphrase="auditor_pass"))
        with open(AUDITOR_RSA_PUB_FILE, "wb") as f:
            f.write(key.public_key().export_key())

    # Paillier
    if not os.path.exists(PAILLIER_PRIV_FILE):
        pub, priv = paillier.generate_paillier_keypair(n_length=1024)
        with open(PAILLIER_PUB_FILE, "w") as f:
            f.write(json.dumps({'n': str(pub.n)}))
        with open(PAILLIER_PRIV_FILE, "w") as f:
            f.write(json.dumps({'p': str(priv.p), 'q': str(priv.q)}))

    with open(AUDITOR_RSA_PUB_FILE, "rb") as f:
        auditor_rsa_pub_pem = f.read().decode('utf-8')

    with open(PAILLIER_PUB_FILE, "r") as f:
        paillier_pub_data = json.load(f)
        paillier_pub = paillier.PaillierPublicKey(int(paillier_pub_data['n']))
        paillier_pub_n_str = paillier_pub_data['n']

    with open(PAILLIER_PRIV_FILE, "r") as f:
        paillier_priv_data = json.load(f)
        paillier_priv = paillier.PaillierPrivateKey(
            paillier_pub,
            int(paillier_priv_data['p']),
            int(paillier_priv_data['q'])
        )

    with open(AUDITOR_RSA_PRIV_FILE, "rb") as f:
        auditor_rsa_priv_pem = f.read()

    return auditor_rsa_pub_pem, paillier_pub, paillier_priv, paillier_pub_n_str, auditor_rsa_priv_pem

AUDITOR_RSA_PUB_PEM, PAILLIER_PUB, PAILLIER_PRIV, PAILLIER_PUB_N_STR, AUDITOR_RSA_PRIV_PEM = init_keys()

# ---------- HANDLERS (doctor + auditor) ----------
def handle_get_public_info(body):
    return {
        "status": "ok",
        "auditor_rsa_pub_pem": AUDITOR_RSA_PUB_PEM,
        "paillier_pub_n": PAILLIER_PUB_N_STR
    }

def handle_register_doctor(body):
    doc_id = body.get("doctor_id", "").strip()
    ecdsa_pub_pem = body.get("ecdsa_pub_pem")
    dept_paillier_b64 = body.get("dept_paillier_b64")
    if not doc_id.isalnum() or not ecdsa_pub_pem or not dept_paillier_b64:
        return {"status": "error", "error": "Missing or invalid fields"}
    doctors = read_json_db(DOCTORS_FILE, {})
    if doc_id in doctors:
        return {"status": "error", "error": "Doctor ID exists"}
    doctors[doc_id] = {
        "ecdsa_pub_pem": ecdsa_pub_pem,
        "dept_paillier_b64": dept_paillier_b64
    }
    write_json_db(DOCTORS_FILE, doctors)
    print(f"[server] Registered doctor: {doc_id}")
    return {"status": "ok"}

def handle_upload_report(body):
    doc_id = body.get("doctor_id")
    doctors = read_json_db(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status": "error", "error": "Unknown doctor"}
    required = ["filename", "timestamp", "encrypted_aes_key_b64", "aes_gcm_nonce_b64",
                "aes_gcm_tag_b64", "aes_gcm_ciphertext_b64", "ecdsa_signature_b64"]
    for k in required:
        if k not in body:
            return {"status": "error", "error": f"Missing field {k}"}
    report_blob = {
        "doctor_id": doc_id,
        "filename": body["filename"],
        "timestamp": body["timestamp"],
        "encrypted_aes_key_b64": body["encrypted_aes_key_b64"],
        "aes_gcm_nonce_b64": body["aes_gcm_nonce_b64"],
        "aes_gcm_tag_b64": body["aes_gcm_tag_b64"],
        "aes_gcm_ciphertext_b64": body["aes_gcm_ciphertext_b64"],
        "ecdsa_signature_b64": body["ecdsa_signature_b64"]
    }
    report_id = f"rep_{int(time.time())}_{doc_id}"
    reports = read_json_db(REPORTS_FILE, {})
    reports[report_id] = report_blob
    write_json_db(REPORTS_FILE, reports)
    print(f"[server] Stored encrypted report {report_id} from {doc_id}")
    return {"status": "ok", "report_id": report_id}

def handle_submit_expense(body):
    doc_id = body.get("doctor_id")
    if doc_id not in read_json_db(DOCTORS_FILE, {}):
        return {"status": "error", "error": "Unknown doctor"}
    expense_paillier_b64 = body.get("expense_paillier_b64")
    if not expense_paillier_b64:
        return {"status": "error", "error": "Missing expense ciphertext"}
    expense_id = f"exp_{int(time.time())}_{doc_id}"
    expenses = read_json_db(EXPENSES_FILE, {})
    expenses[expense_id] = {
        "doctor_id": doc_id,
        "expense_paillier_b64": expense_paillier_b64
    }
    write_json_db(EXPENSES_FILE, expenses)
    print(f"[server] Stored encrypted expense for {doc_id}")
    return {"status": "ok"}

# ---------- Auditor handlers ----------
def handle_audit_list_doctors(body):
    doctors = read_json_db(DOCTORS_FILE, {})
    doc_list = [{"id": doc_id} for doc_id in doctors.keys()]
    return {"status": "ok", "doctors": doc_list}

def handle_audit_search_dept(body):
    keyword = body.get("keyword", "").strip().lower()
    if not keyword:
        return {"status": "error", "error": "Missing keyword"}
    try:
        kw_hash = int.from_bytes(hashlib.sha256(keyword.encode()).digest(), 'big')
        enc_kw = PAILLIER_PUB.encrypt(kw_hash)
    except Exception as e:
        return {"status": "error", "error": f"Keyword encryption failed: {e}"}
    doctors = read_json_db(DOCTORS_FILE, {})
    matches = []
    for doc_id, info in doctors.items():
        try:
            c_data = json.loads(b64d(info["dept_paillier_b64"]))
            enc_dept = paillier.EncryptedNumber(
                PAILLIER_PUB,
                int(c_data['ciphertext']),
                int(c_data['exponent'])
            )
            diff = enc_dept - enc_kw
            if PAILLIER_PRIV.decrypt(diff) == 0:
                matches.append(doc_id)
        except Exception:
            continue
    print(f"[server] Auditor search for '{keyword}' found {len(matches)} matches.")
    return {"status": "ok", "matches": matches}

def handle_audit_sum_expenses(body):
    expenses = read_json_db(EXPENSES_FILE, {})
    if not expenses:
        return {"status": "ok", "total_sum": 0, "count": 0}
    total = PAILLIER_PUB.encrypt(0)
    count = 0
    for expense_id, info in expenses.items():
        try:
            e_data = json.loads(b64d(info["expense_paillier_b64"]))
            enc_exp = paillier.EncryptedNumber(
                PAILLIER_PUB,
                int(e_data['ciphertext']),
                int(e_data['exponent'])
            )
            total += enc_exp
            count += 1
        except Exception:
            continue
    final_sum = PAILLIER_PRIV.decrypt(total)
    print(f"[server] Auditor summed {count} expenses. Total: {final_sum}")
    return {"status": "ok", "total_sum": final_sum, "count": count}

def handle_audit_list_reports(body):
    reports = read_json_db(REPORTS_FILE, {})
    report_list = [
        {"id": rep_id, "doc_id": info["doctor_id"], "file": info["filename"], "ts": info["timestamp"]}
        for rep_id, info in reports.items()
    ]
    return {"status": "ok", "reports": report_list}

def handle_audit_get_report_blob(body):
    report_id = body.get("report_id")
    reports = read_json_db(REPORTS_FILE, {})
    if report_id not in reports:
        return {"status": "error", "error": "Report not found"}
    return {"status": "ok", "report_data": reports[report_id]}

def handle_get_doctor_pubkey(body):
    doc_id = body.get("doctor_id")
    doctors = read_json_db(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status": "error", "error": "Doctor not found"}
    return {"status": "ok", "ecdsa_pub_pem": doctors[doc_id]["ecdsa_pub_pem"]}

# ---------- Socket Server ----------
class ThreadedTCPRequestHandler(socketserver.StreamRequestHandler):
    HANDLER_MAP = {
        "doctor": {
            "get_public_info": handle_get_public_info,
            "register_doctor": handle_register_doctor,
            "upload_report": handle_upload_report,
            "submit_expense": handle_submit_expense,
        },
        "auditor": {
            "get_public_info": handle_get_public_info,
            "audit_list_doctors": handle_audit_list_doctors,
            "audit_search_dept": handle_audit_search_dept,
            "audit_sum_expenses": handle_audit_sum_expenses,
            "audit_list_reports": handle_audit_list_reports,
            "audit_get_report_blob": handle_audit_get_report_blob,
            "get_doctor_pubkey": handle_get_doctor_pubkey,
        }
    }
    def handle(self):
        try:
            data = self.rfile.readline().strip()
            if not data:
                return
            req = json.loads(data.decode('utf-8'))
            action = req.get("action")
            role = req.get("role")
            body = req.get("body", {})
            if role in self.HANDLER_MAP and action in self.HANDLER_MAP[role]:
                handler_func = self.HANDLER_MAP[role][action]
                resp = handler_func(body)
            else:
                resp = {"status": "error", "error": f"Unknown action '{action}' for role '{role}'"}
        except json.JSONDecodeError:
            resp = {"status": "error", "error": "Invalid JSON request"}
        except Exception as e:
            print(f"[server] Error handling request: {e}")
            resp = {"status": "error", "error": f"Internal server error: {e}"}
        try:
            self.wfile.write((json.dumps(resp) + "\n").encode('utf-8'))
        except BrokenPipeError:
            pass

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

# ---------- Server-side Auditor Console (uses private key) ----------
def server_auditor_load_privkey(passphrase="auditor_pass"):
    try:
        key = RSA.import_key(AUDITOR_RSA_PRIV_PEM, passphrase=passphrase)
        return key
    except Exception as e:
        print(f"[server-auditor] Failed to import auditor private key: {e}")
        return None

def server_auditor_list_doctors():
    resp = handle_audit_list_doctors({})
    if resp.get("status") == "ok":
        print("\n--- Registered Doctors ---")
        for doc in resp.get("doctors", []):
            print(f"- ID: {doc['id']}")
    else:
        print(f"[server-auditor] Error: {resp.get('error')}")

def server_auditor_search_dept():
    keyword = input("Enter department keyword to search: ").strip().lower()
    if not keyword:
        print("[server-auditor] Empty keyword")
        return
    resp = handle_audit_search_dept({"keyword": keyword})
    if resp.get("status") == "ok":
        matches = resp.get("matches", [])
        print(f"\n--- Search Results for '{keyword}' ---")
        if not matches:
            print("No matches found.")
        for doc_id in matches:
            print(f"- Found Doctor ID: {doc_id}")
    else:
        print(f"[server-auditor] Error: {resp.get('error')}")

def server_auditor_sum_expenses():
    print("\n[server-auditor] Requesting homomorphic sum of all expenses from server...")
    resp = handle_audit_sum_expenses({})
    if resp.get("status") == "ok":
        print(f"\n--- Total Expenses (All Doctors) ---")
        print(f"  Total Amount: ${resp.get('total_sum')}")
        print(f"  Entry Count:   {resp.get('count')}")
    else:
        print(f"[server-auditor] Error: {resp.get('error')}")

def server_auditor_list_and_audit():
    privkey = server_auditor_load_privkey()
    if not privkey:
        print("[server-auditor] Cannot load auditor private key; aborting.")
        return
    resp = handle_audit_list_reports({})
    if resp.get("status") != "ok":
        print(f"[server-auditor] Could not list reports: {resp.get('error')}")
        return
    reports = resp.get("reports", [])
    if not reports:
        print("[server-auditor] No reports available.")
        return
    print("\n--- Encrypted Reports on Server ---")
    for i, rep in enumerate(reports):
        print(f"  {i + 1}. ID: {rep['id']} | File: {rep['file']} | Doctor: {rep['doc_id']} | TS: {rep['ts']}")
    try:
        choice = int(input("Select report # to audit/decrypt: ")) - 1
        report_to_audit = reports[choice]
    except (IndexError, ValueError):
        print("[server-auditor] Invalid selection.")
        return
    print(f"[server-auditor] Auditing Report ID: {report_to_audit['id']}...")
    blob_resp = handle_audit_get_report_blob({"report_id": report_to_audit['id']})
    if blob_resp.get("status") != "ok":
        print(f"[server-auditor] Could not fetch report blob: {blob_resp.get('error')}")
        return
    blob = blob_resp.get("report_data")
    key_resp = handle_get_doctor_pubkey({"doctor_id": blob['doctor_id']})
    if key_resp.get("status") != "ok":
        print(f"[server-auditor] Could not fetch doctor's pubkey: {key_resp.get('error')}")
        return
    try:
        doctor_ecdsa_pub = ch_serialization.load_pem_public_key(
            key_resp['ecdsa_pub_pem'].encode('utf-8')
        )
    except Exception as e:
        print(f"[server-auditor] Failed to parse doctor's ECDSA key: {e}")
        return
    try:
        # Decrypt AES with auditor RSA privkey
        cipher_rsa = PKCS1_OAEP.new(privkey)
        aes_key = cipher_rsa.decrypt(b64d(blob['encrypted_aes_key_b64']))
        nonce = b64d(blob['aes_gcm_nonce_b64'])
        tag = b64d(blob['aes_gcm_tag_b64'])
        ciphertext = b64d(blob['aes_gcm_ciphertext_b64'])
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag)
        report_hash = hashlib.sha256(plaintext_bytes).digest()
        signature = b64d(blob['ecdsa_signature_b64'])
        data_that_was_signed = report_hash + blob['timestamp'].encode('utf-8')
        doctor_ecdsa_pub.verify(
            signature,
            data_that_was_signed,
            ch_ec.ECDSA(ch_hashes.SHA256())
        )
        print(f"[server-auditor] Report decrypted and signature verified.")
        print("-" * 40)
        print(plaintext_bytes.decode('utf-8'))
        print("-" * 40)
        out_dir = os.path.join(DATA_DIR, "auditor_decrypted_reports")
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        out_path = os.path.join(out_dir, f"{report_to_audit['id']}.txt")
        with open(out_path, "wb") as f:
            f.write(plaintext_bytes)
        print(f"[server-auditor] Decrypted copy stored at: {out_path}")
    except (ValueError, ChInvalidSignature):
        print("[server-auditor] AUDIT FAILED: signature invalid or decryption failed.")
    except Exception as e:
        print(f"[server-auditor] Audit failed: {e}")

def run_auditor_console():
    print("\n--- Auditor Console (server-side) ---")
    privkey_ok = True if server_auditor_load_privkey() is not None else False
    if not privkey_ok:
        print("[server-auditor] Auditor private key not usable. Some functions will fail.")
    while True:
        print("\nAuditor Menu:")
        print("1. List Registered Doctors")
        print("2. Search Doctors by Department (Homomorphic)")
        print("3. Sum All Expenses (Homomorphic)")
        print("4. List & Audit Encrypted Reports (Local Decryption)")
        print("0. Exit Auditor Console")
        choice = input("Choice: ").strip()
        if choice == "1":
            server_auditor_list_doctors()
        elif choice == "2":
            server_auditor_search_dept()
        elif choice == "3":
            server_auditor_sum_expenses()
        elif choice == "4":
            server_auditor_list_and_audit()
        elif choice == "0":
            print("[server-auditor] Exiting Auditor Console.")
            break
        else:
            print("[server-auditor] Invalid choice.")

# ---------- PLACEHOLDERS & ALTERNATIVES (COMMENTED) ----------
# The sections below are intentionally commented. Uncomment the block you need
# and adapt the call sites earlier in the file accordingly (search for
# "### ALTERNATE" in client/server).
#
# Examples included:
# - ElGamal asymmetric wrap (PyCryptodome)
# - RSA-sign as alternate to ECDSA
# - Hashing ciphertexts (SHA256 / MD5 / BLAKE2)
# - AES-CBC placeholder (with PKCS7) if GCM not requested
# - Diffie-Hellman key agreement skeleton
#
# NOTE: These are educational examples — in an exam, you may uncomment one
# technique and ensure the client does the complementary steps.

### PLACEHOLDER: ElGamal asymmetric wrap for AES key (example)
"""
### UNCOMMENT TO USE ELGAMAL WRAP (server-side)
### --- ElGamal WRAP/UNWRAP IMPLEMENTATION --- ###
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import bytes_to_long, long_to_bytes

def elgamal_generate_keys():
    key = ElGamal.generate(2048, random.StrongRandom().randint)
    return key.export_key(), key.publickey().export_key()

def elgamal_encrypt(pubkey_pem, aes_key: bytes):
    pub = ElGamal.import_key(pubkey_pem)
    m = bytes_to_long(aes_key)
    k = random.StrongRandom().randint(1, pub.p-2)
    # c1 = g^k mod p ; c2 = m * (y^k mod p) mod p
    c1 = pow(pub.g, k, pub.p)
    c2 = (m * pow(pub.y, k, pub.p)) % pub.p
    return {"c1": str(c1), "c2": str(c2)}

def elgamal_decrypt(privkey_pem, c1: int, c2: int):
    priv = ElGamal.import_key(privkey_pem)
    s = pow(c1, priv.x, priv.p)  # shared secret
    # m = c2 * s^-1 mod p
    s_inv = pow(s, -1, priv.p)
    m = (c2 * s_inv) % priv.p
    aes_key = long_to_bytes(m)
    return aes_key.ljust(32, b"\x00")  # pad to 32 bytes if needed

    


    Client (when sending report)

# replace RSA wrap line with:
enc = elgamal_encrypt(state["server_keys"]["elgamal_pub"], aes_key)
body["elgamal_c1"] = enc["c1"]
body["elgamal_c2"] = enc["c2"]



Server (when auditing)

aes_key = elgamal_decrypt(
    AUDITOR_ELGAMAL_PRIV_PEM,
    int(blob["elgamal_c1"]),
    int(blob["elgamal_c2"])
)
"""



"""
### UNCOMMENT TO USE ECC

### --- ECC ECIES-STYLE HYBRID ENCRYPTION --- ###
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def ecc_generate_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    return (
        priv.private_bytes(
            encoding=ch_serialization.Encoding.PEM,
            format=ch_serialization.PrivateFormat.PKCS8,
            encryption_algorithm=ch_serialization.NoEncryption()
        ).decode(),
        pub.public_bytes(
            encoding=ch_serialization.Encoding.PEM,
            format=ch_serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    )

def ecc_encrypt(pub_pem, aes_key: bytes):
    peer_pub = ch_serialization.load_pem_public_key(pub_pem.encode())
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    shared = ephemeral.exchange(ec.ECDH(), peer_pub)
    
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies"
    ).derive(shared)

    nonce = get_random_bytes(12)
    cipher = Cipher(algorithms.AES(derived), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ct = encryptor.update(aes_key) + encryptor.finalize()
    tag = encryptor.tag

    ephemeral_pub = ephemeral.public_key().public_bytes(
        ch_serialization.Encoding.PEM,
        ch_serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return {"ephemeral_pub": ephemeral_pub, "nonce": b64e(nonce),
            "ct": b64e(ct), "tag": b64e(tag)}

def ecc_decrypt(priv_pem, ephemeral_pub, nonce, ct, tag):
    priv = ch_serialization.load_pem_private_key(priv_pem.encode(), password=None)
    eph_pub = ch_serialization.load_pem_public_key(ephemeral_pub.encode())

    shared = priv.exchange(ec.ECDH(), eph_pub)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies"
    ).derive(shared)

    cipher = Cipher(algorithms.AES(derived), modes.GCM(b64d(nonce), b64d(tag)))
    decryptor = cipher.decryptor()
    aes_key = decryptor.update(b64d(ct)) + decryptor.finalize()
    return aes_key

    
    Client send:

enc = ecc_encrypt(state["server_keys"]["ecc_pub"], aes_key)
body["ecc_ephemeral"] = enc["ephemeral_pub"]
body["ecc_nonce"] = enc["nonce"]
body["ecc_ct"] = enc["ct"]
body["ecc_tag"] = enc["tag"]


Server audit decrypt:

aes_key = ecc_decrypt(
    SERVER_ECC_PRIV_PEM,
    blob["ecc_ephemeral"],
    blob["ecc_nonce"],
    blob["ecc_ct"],
    blob["ecc_tag"]
)
"""
### PLACEHOLDER: RSA signature verification (server-side as alternative)
"""
### UNCOMMENT TO USE RSA SIGNATURE verification (server-side)
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
def verify_rsa_signature(pubkey_pem: bytes, signature: bytes, message: bytes):
    pub = RSA.import_key(pubkey_pem)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(pub).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
"""

### PLACEHOLDER: Hash AES ciphertext before signing / or as extra layer
"""
### UNCOMMENT TO HASH AES CIPHERTEXT (server-side or client-side)
def hash_ciphertext_sha256(ciphertext: bytes) -> bytes:
    return hashlib.sha256(ciphertext).digest()

def hash_ciphertext_md5(ciphertext: bytes) -> bytes:
    return hashlib.md5(ciphertext).digest()

def hash_ciphertext_blake2b(ciphertext: bytes) -> bytes:
    import hashlib
    h = hashlib.blake2b()
    h.update(ciphertext)
    return h.digest()
"""

### PLACEHOLDER: AES-CBC with PKCS7 (alternate symmetric mode)
"""
### UNCOMMENT TO USE AES-CBC (client/server)
from Crypto.Util.Padding import pad, unpad
def aes_cbc_encrypt(aes_key: bytes, plaintext: bytes):
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv, ct

def aes_cbc_decrypt(aes_key: bytes, iv: bytes, ciphertext: bytes):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt
"""

### PLACEHOLDER: Diffie-Hellman skeleton (for key agreement)
"""
### UNCOMMENT TO USE DIFFIE-HELLMAN (skeleton only)
from Crypto.Random import random
def dh_generate_private(p):
    return random.StrongRandom().randint(2, p-2)

def dh_generate_public(g, priv, p):
    return pow(g, priv, p)

def dh_compute_shared(pub_other, priv, p):
    return pow(pub_other, priv, p)
# Example primes/g/generation: use RFC-defined groups or Crypto library wrappers.
"""

# ---------- SERVER START ----------
def start_server():
    print(f"[server] Starting server on {HOST}:{PORT} ...")
    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print("[server] Listening for connections.")
    try:
        run_auditor_console()
    finally:
        print("[server] Shutting down server...")
        server.shutdown()
        server.server_close()
        print("[server] Server stopped.")

if __name__ == "__main__":
    start_server()
