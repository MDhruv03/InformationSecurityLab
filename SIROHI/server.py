#!/usr/bin/env python3
"""
is_lab_complex_server.py

A more complex, privacy-preserving medical records server.

Architecture:
- This server acts as an untrusted, cryptographically-enabled storage provider.
- It NEVER stores plaintext medical reports or plaintext department names.
- It holds the Paillier keypair to perform aggregate analysis (summing expenses,
  searching departments) on behalf of the auditor.
- It holds the Auditor's RSA Public Key, allowing doctors to encrypt reports
  that ONLY the auditor can read.
"""
import os
import json
import threading
import socketserver
import base64
import time
import hashlib
from Crypto.PublicKey import RSA
from phe import paillier

# --- Configuration ---
DATA_DIR = "server_data_complex"
DOCTORS_FILE = os.path.join(DATA_DIR, "doctors_db.json")
EXPENSES_FILE = os.path.join(DATA_DIR, "expenses_db.json")
REPORTS_FILE = os.path.join(DATA_DIR, "reports_db.json")
CONFIG_FILE = os.path.join(DATA_DIR, "server_config.json")
AUDITOR_RSA_PRIV_FILE = os.path.join(DATA_DIR, "auditor_rsa_key.pem")
AUDITOR_RSA_PUB_FILE = os.path.join(DATA_DIR, "auditor_rsa_key.pub")
PAILLIER_PRIV_FILE = os.path.join(DATA_DIR, "paillier.key")
PAILLIER_PUB_FILE = os.path.join(DATA_DIR, "paillier.pub")
HOST, PORT = "127.0.0.1", 5001
lock = threading.Lock()


# --- Utility Functions ---

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


# --- Key Management ---

def init_keys():
    """Load or generate all necessary server-side and auditor keys."""
    os.makedirs(DATA_DIR, exist_ok=True)

    # 1. Auditor's RSA Keypair (for report decryption)
    if not os.path.exists(AUDITOR_RSA_PRIV_FILE):
        print("Generating new Auditor RSA-2048 keypair...")
        key = RSA.generate(2048)
        with open(AUDITOR_RSA_PRIV_FILE, "wb") as f:
            f.write(key.export_key(passphrase="auditor_pass"))  # Demo password
        with open(AUDITOR_RSA_PUB_FILE, "wb") as f:
            f.write(key.public_key().export_key())
        print("Auditor keys generated (auditor_rsa_key.pem, auditor_rsa_key.pub)")

    # 2. Server's Paillier Keypair (for homomorphic services)
    if not os.path.exists(PAILLIER_PRIV_FILE):
        print("Generating new Paillier 1024-bit keypair...")
        pub, priv = paillier.generate_paillier_keypair(n_length=1024)
        with open(PAILLIER_PUB_FILE, "w") as f:
            f.write(json.dumps({'n': str(pub.n)}))
        with open(PAILLIER_PRIV_FILE, "w") as f:
            f.write(json.dumps({'p': str(priv.p), 'q': str(priv.q)}))
        print("Paillier keys generated (paillier.pub, paillier.key)")

    # Load keys into memory
    with open(AUDITOR_RSA_PUB_FILE, "rb") as f:
        AUDITOR_RSA_PUB_PEM = f.read().decode('utf-8')

    with open(PAILLIER_PUB_FILE, "r") as f:
        paillier_pub_data = json.load(f)
        PAILLIER_PUB = paillier.PaillierPublicKey(int(paillier_pub_data['n']))
        PAILLIER_PUB_N_STR = paillier_pub_data['n']

    with open(PAILLIER_PRIV_FILE, "r") as f:
        paillier_priv_data = json.load(f)
        PAILLIER_PRIV = paillier.PaillierPrivateKey(
            PAILLIER_PUB,
            int(paillier_priv_data['p']),
            int(paillier_priv_data['q'])
        )

    print("Server keys loaded.")
    return AUDITOR_RSA_PUB_PEM, PAILLIER_PUB, PAILLIER_PRIV, PAILLIER_PUB_N_STR


# --- Global Key Variables ---
AUDITOR_RSA_PUB_PEM, PAILLIER_PUB, PAILLIER_PRIV, PAILLIER_PUB_N_STR = init_keys()


# --- Request Handler Functions ---

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
        return {"status": "error", "error": "Missing fields"}

    doctors = read_json_db(DOCTORS_FILE, {})
    if doc_id in doctors:
        return {"status": "error", "error": "Doctor ID already exists"}

    doctors[doc_id] = {
        "ecdsa_pub_pem": ecdsa_pub_pem,
        "dept_paillier_b64": dept_paillier_b64
        # NOTE: Server *NEVER* stores the plaintext department.
    }
    write_json_db(DOCTORS_FILE, doctors)
    print(f"[+] Registered doctor: {doc_id}")
    return {"status": "ok"}


def handle_upload_report(body):
    doc_id = body.get("doctor_id")
    if doc_id not in read_json_db(DOCTORS_FILE, {}):
        return {"status": "error", "error": "Unknown doctor"}

    # Server just validates fields exist and stores the opaque blob.
    # It CANNOT decrypt any of this.
    try:
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
        print(f"[+] Stored encrypted report {report_id} from {doc_id}")
        return {"status": "ok", "report_id": report_id}
    except KeyError:
        return {"status": "error", "error": "Missing report fields"}


def handle_submit_expense(body):
    doc_id = body.get("doctor_id")
    if doc_id not in read_json_db(DOCTORS_FILE, {}):
        return {"status": "error", "error": "Unknown doctor"}

    # Server stores the Paillier ciphertext. It cannot decrypt it.
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
    print(f"[+] Stored encrypted expense for {doc_id}")
    return {"status": "ok"}


# --- Auditor-Only Handler Functions ---

def handle_audit_list_doctors(body):
    doctors = read_json_db(DOCTORS_FILE, {})
    # Return only non-sensitive data
    doc_list = [{"id": doc_id} for doc_id in doctors.keys()]
    return {"status": "ok", "doctors": doc_list}


def handle_audit_search_dept(body):
    keyword = body.get("keyword", "").strip().lower()
    if not keyword:
        return {"status": "error", "error": "Missing keyword"}

    # Server uses its Paillier keys to perform a privacy-preserving check
    try:
        kw_hash = int.from_bytes(hashlib.sha256(keyword.encode()).digest(), 'big')
        enc_kw = PAILLIER_PUB.encrypt(kw_hash)
    except Exception as e:
        return {"status": "error", "error": f"Keyword encryption failed: {e}"}

    doctors = read_json_db(DOCTORS_FILE, {})
    matches = []

    for doc_id, info in doctors.items():
        try:
            # Reconstruct EncryptedNumber from stored blob
            c_data = json.loads(b64d(info["dept_paillier_b64"]))
            enc_dept = paillier.EncryptedNumber(
                PAILLIER_PUB,
                int(c_data['ciphertext']),
                int(c_data['exponent'])
            )

            # Homomorphic equality check: decrypt(A - B) == 0
            diff = enc_dept - enc_kw
            if PAILLIER_PRIV.decrypt(diff) == 0:
                matches.append(doc_id)
        except Exception:
            continue  # Skip corrupted data

    print(f"[+] Auditor search for '{keyword}' found {len(matches)} matches.")
    return {"status": "ok", "matches": matches}


def handle_audit_sum_expenses(body):
    expenses = read_json_db(EXPENSES_FILE, {})
    if not expenses:
        return {"status": "ok", "total_sum": 0, "count": 0}

    # Server uses Paillier keys to homomorphically sum all expenses
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

    # Server decrypts ONLY THE FINAL SUM
    final_sum = PAILLIER_PRIV.decrypt(total)
    print(f"[+] Auditor summed {count} expenses. Total: {final_sum}")
    return {"status": "ok", "total_sum": final_sum, "count": count}


def handle_audit_list_reports(body):
    reports = read_json_db(REPORTS_FILE, {})
    # Return metadata only, not the encrypted blobs
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

    # Send the full encrypted blob to the auditor for local decryption
    return {"status": "ok", "report_data": reports[report_id]}


def handle_get_doctor_pubkey(body):
    doc_id = body.get("doctor_id")
    doctors = read_json_db(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status": "error", "error": "Doctor not found"}

    return {"status": "ok", "ecdsa_pub_pem": doctors[doc_id]["ecdsa_pub_pem"]}


# --- Main Server Class ---

class ThreadedTCPRequestHandler(socketserver.StreamRequestHandler):
    """Handler for each client connection."""

    HANDLER_MAP = {
        "doctor": {
            "get_public_info": handle_get_public_info,
            "register_doctor": handle_register_doctor,
            "upload_report": handle_upload_report,
            "submit_expense": handle_submit_expense,
        },
        "auditor": {
            "get_public_info": handle_get_public_info,  # Auditors can also see pubkeys
            "audit_list_doctors": handle_audit_list_doctors,
            "audit_search_dept": handle_audit_search_dept,
            "audit_sum_expenses": handle_audit_sum_expenses,
            "audit_list_reports": handle_audit_list_reports,
            "audit_get_report_blob": handle_audit_get_report_blob,
            "get_doctor_pubkey": handle_get_doctor_pubkey,
        }
    }

    def handle(self):
        client_ip = self.client_address[0]
        try:
            data = self.rfile.readline().strip()
            if not data:
                return

            req = json.loads(data.decode('utf-8'))
            action = req.get("action")
            role = req.get("role")
            body = req.get("body", {})

            # Find the correct handler function
            if role in self.HANDLER_MAP and action in self.HANDLER_MAP[role]:
                handler_func = self.HANDLER_MAP[role][action]
                resp = handler_func(body)
            else:
                resp = {"status": "error", "error": f"Unknown action '{action}' for role '{role}'"}

        except json.JSONDecodeError:
            resp = {"status": "error", "error": "Invalid JSON request"}
        except Exception as e:
            print(f"[!] Server error: {e}")
            resp = {"status": "error", "error": f"Internal server error: {e}"}

        try:
            self.wfile.write((json.dumps(resp) + "\n").encode('utf-8'))
        except BrokenPipeError:
            print(f"Client {client_ip} disconnected.")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def start_server():
    print(f"Starting server on {HOST}:{PORT}...")
    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    with server:
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        print(f"[✅] Server listening on {HOST}:{PORT}")
        print("Press Enter to stop server.")
        try:
            # Keep main thread alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down server...")
            server.shutdown()
            print("Server stopped.")


if __name__ == "__main__":
    start_server()