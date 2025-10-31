"""
merged_server.py
Unified server that supports multiple algorithms:
- asymmetric key transport: RSA-OAEP (default), ElGamal (implemented), ECC ECIES (optional)
- symmetric: AES-GCM (default), AES-CBC (placeholder)
- signatures: ECDSA (default verify), RSA-verify, ElGamal-verify (supports r/s)
- searchable dept: Paillier (default) or SSE
- expenses: Paillier HE (sum), RSA-homo, ElGamal-homo (store)

Run:
    python merged_server.py

Auditor console runs in the same process (select option 4 to decrypt & audit).
"""
import os
import json
import threading
import socketserver
import base64
import time
import hashlib
from pathlib import Path

# crypto libs
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
from phe import paillier

# ECC (ECIES-style)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as ch_hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization as ch_serialization
from cryptography.exceptions import InvalidSignature as ChInvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec as ch_ec

# ---------- CONFIG ----------
DATA_DIR = "server_data"
DOCTORS_FILE = os.path.join(DATA_DIR, "doctors_db.json")
EXPENSES_FILE = os.path.join(DATA_DIR, "expenses_db.json")
REPORTS_FILE = os.path.join(DATA_DIR, "reports_db.json")
AUDITOR_RSA_PRIV_FILE = os.path.join(DATA_DIR, "auditor_rsa_key.pem")
AUDITOR_RSA_PUB_FILE = os.path.join(DATA_DIR, "auditor_rsa_key.pub")
HOST = "127.0.0.1"
PORT = 5001
lock = threading.Lock()

# ---------- UTILITIES ----------
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

# ---------- KEY INIT ----------
def init_server_keys():
    os.makedirs(DATA_DIR, exist_ok=True)
    # Auditor RSA (used to unwrap AES keys by auditor)
    if not os.path.exists(AUDITOR_RSA_PRIV_FILE):
        key = RSA.generate(2048)
        with open(AUDITOR_RSA_PRIV_FILE, "wb") as f:
            # no passphrase for simplicity
            f.write(key.export_key())
        with open(AUDITOR_RSA_PUB_FILE, "wb") as f:
            f.write(key.public_key().export_key())
    with open(AUDITOR_RSA_PUB_FILE, "rb") as f:
        auditor_rsa_pub_pem = f.read().decode('utf-8')
    with open(AUDITOR_RSA_PRIV_FILE, "rb") as f:
        auditor_rsa_priv_pem = f.read().decode('utf-8')
    # Paillier (for searchable dept + HE expenses)
    paillier_pubfile = os.path.join(DATA_DIR, "paillier.pub")
    paillier_privfile = os.path.join(DATA_DIR, "paillier.priv")
    if not os.path.exists(paillier_privfile):
        pub, priv = paillier.generate_paillier_keypair(n_length=1024)
        with open(paillier_pubfile, "w") as f:
            f.write(json.dumps({"n": str(pub.n)}))
        with open(paillier_privfile, "w") as f:
            f.write(json.dumps({"p": str(priv.p), "q": str(priv.q)}))
    with open(paillier_pubfile, "r") as f:
        pubdata = json.load(f)
        paillier_pub = paillier.PaillierPublicKey(int(pubdata["n"]))
        paillier_pub_n_str = pubdata["n"]
    with open(paillier_privfile, "r") as f:
        privdata = json.load(f)
        paillier_priv = paillier.PaillierPrivateKey(paillier_pub, int(privdata["p"]), int(privdata["q"]))
    return auditor_rsa_pub_pem, auditor_rsa_priv_pem, paillier_pub, paillier_priv, paillier_pub_n_str

AUDITOR_RSA_PUB_PEM, AUDITOR_RSA_PRIV_PEM, PAILLIER_PUB, PAILLIER_PRIV, PAILLIER_PUB_N_STR = init_server_keys()

# ---------- ElGamal wrap (works with PyCryptodome ElGamal keys exported) ----------
# Note: We assume client sends ElGamal public params as dict {"p","g","y"} and
# for private key server stores {"p","g","x"} — see placeholders in client.
def elgamal_decrypt_bytes(priv_params: dict, c1_str: str, c2_str: str) -> bytes:
    """
    priv_params: dict with ints 'p','g','x'
    c1_str/c2_str: decimal strings
    returns padded bytes representing AES key (we pad/truncate to 32 bytes)
    """
    p = int(priv_params["p"]); x = int(priv_params["x"])
    c1 = int(c1_str); c2 = int(c2_str)
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)
    m = (c2 * s_inv) % p
    b = long_to_bytes(m)
    # ensure 32 bytes for AES-256 (right-pad with zeros if necessary)
    if len(b) >= 32:
        return b[:32]
    return b.ljust(32, b"\x00")

# ---------- ECC ECIES-style decrypt (server) ----------
def ecc_decrypt_aeskey(priv_pem: str, ephemeral_pub_pem: str, nonce_b64: str, ct_b64: str, tag_b64: str) -> bytes:
    priv = ch_serialization.load_pem_private_key(priv_pem.encode(), password=None)
    eph_pub = ch_serialization.load_pem_public_key(ephemeral_pub_pem.encode())
    shared = priv.exchange(ec.ECDH(), eph_pub)
    derived = HKDF(
        algorithm=ch_hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies"
    ).derive(shared)
    nonce = b64d(nonce_b64)
    ct = b64d(ct_b64)
    tag = b64d(tag_b64)
    cipher = Cipher(algorithms.AES(derived), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    aes_key = decryptor.update(ct) + decryptor.finalize()
    return aes_key

# ---------- HANDLERS ----------
def handle_get_public_info(body):
    return {
        "status": "ok",
        "auditor_rsa_pub_pem": AUDITOR_RSA_PUB_PEM,
        "paillier_pub_n": PAILLIER_PUB_N_STR
    }

def handle_register_doctor(body):
    doc_id = body.get("doctor_id", "").strip()
    sig_pub = body.get("sig_pub")  # can contain rsa_pub_pem, ecdsa_pub_pem, elgamal_pub params
    dept_payload = body.get("dept_payload")
    alg_dept_enc = body.get("alg_dept_enc", "Paillier")
    if not doc_id or not sig_pub or not dept_payload:
        return {"status": "error", "error": "Missing fields"}
    doctors = read_json_db(DOCTORS_FILE, {})
    if doc_id in doctors:
        return {"status": "error", "error": "Doctor ID exists"}
    # Normalize dept payload: store as given (client must follow protocol)
    doctors[doc_id] = {
        "sig_pub": sig_pub,
        "dept_enc": {"alg": alg_dept_enc, "payload": dept_payload},
        "registered_at": time.time()
    }
    write_json_db(DOCTORS_FILE, doctors)
    return {"status": "ok"}

def handle_upload_report(body):
    """
    Expected flexible body:
    {
      doctor_id, filename, timestamp,
      alg_report_enc: "AES-GCM" or "AES-CBC",
      enc_report: {mode:..., nonce/iv, ct, tag?},
      alg_key_enc: "RSA" | "ElGamal" | "ECC",
      key_transport: {enc_key_b64 / elgamal_c1 / elgamal_c2 / ecc_ephemeral...},
      sig: {alg, sig_b64}  OR {r,s} for ElGamal-style
    }
    Response: {"status":"ok","report_id": "...", "sig_ok": bool or null}
    """
    doc_id = body.get("doctor_id")
    doctors = read_json_db(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status": "error", "error": "Unknown doctor"}
    alg_key_enc = body.get("alg_key_enc", "RSA")
    key_transport = body.get("key_transport", {})
    sym_key = None

    # Key transport handling
    try:
        if alg_key_enc == "RSA":
            enc_key_b64 = key_transport.get("enc_key_b64")
            if not enc_key_b64:
                return {"status":"error","error":"missing enc_key_b64 for RSA"}
            rsa_priv = RSA.import_key(AUDITOR_RSA_PRIV_PEM.encode())
            rsa_cipher = PKCS1_OAEP.new(rsa_priv)
            sym_key = rsa_cipher.decrypt(b64d(enc_key_b64))
        elif alg_key_enc == "ElGamal":
            # server must have stored ElGamal priv params for auditor — otherwise error
            # we expect server-side auditor ElGamal priv in a file if used; fall back to error
            el_priv_file = os.path.join(DATA_DIR, "auditor_elgamal_priv.json")
            if not os.path.exists(el_priv_file):
                return {"status":"error","error":"No ElGamal private key on server"}
            with open(el_priv_file, "r") as f:
                priv_params = json.load(f)
            c1 = key_transport.get("elgamal_c1")
            c2 = key_transport.get("elgamal_c2")
            if not c1 or not c2:
                return {"status":"error","error":"missing elgamal c1/c2"}
            sym_key = elgamal_decrypt_bytes(priv_params, c1, c2)
        elif alg_key_enc == "ECC":
            # expect server ECC private to be stored in DATA_DIR as server_ecc_priv.pem
            ecc_priv_file = os.path.join(DATA_DIR, "server_ecc_priv.pem")
            if not os.path.exists(ecc_priv_file):
                return {"status":"error","error":"No ECC priv on server"}
            with open(ecc_priv_file, "r") as f:
                ecc_priv_pem = f.read()
            sym_key = ecc_decrypt_aeskey(
                ecc_priv_pem,
                key_transport.get("ecc_ephemeral"),
                key_transport.get("ecc_nonce"),
                key_transport.get("ecc_ct"),
                key_transport.get("ecc_tag")
            )
        else:
            return {"status":"error","error":"unsupported alg_key_enc"}
    except Exception as e:
        return {"status":"error","error":f"key transport failed: {e}"}

    # decrypt report
    enc_report = body.get("enc_report", {})
    alg_report = body.get("alg_report_enc", "AES-GCM")
    plaintext = None
    try:
        if alg_report in ("AES-GCM", "AES-GCM-256"):
            nonce = b64d(enc_report["nonce"])
            ct = b64d(enc_report["ct"])
            tag = b64d(enc_report["tag"])
            cipher = AES.new(sym_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ct, tag)
        elif alg_report == "AES-CBC":
            from Crypto.Util.Padding import unpad
            iv = b64d(enc_report["iv"])
            ct = b64d(enc_report["ct"])
            cipher = AES.new(sym_key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ct), AES.block_size)
        else:
            return {"status":"error","error":"unsupported alg_report_enc"}
    except Exception as e:
        # store encrypted blob for debugging/audit and still record entry
        plaintext = None
        print(f"[server] symmetric decryption failed: {e}")

    # verify signature (best-effort) using registered pubkey
    sig = body.get("sig", {})
    sig_ok = None
    registered_pub = doctors[doc_id].get("sig_pub", {})
    try:
        if sig:
            if sig.get("alg") == "ECDSA" and registered_pub.get("ecdsa_pub_pem"):
                vk = ch_serialization.load_pem_public_key(registered_pub["ecdsa_pub_pem"].encode())
                data = (hashlib.sha256(plaintext or b"").digest() + body.get("timestamp","").encode())
                vk.verify(b64d(sig["sig_b64"]), data, ch_ec.ECDSA(ch_hashes.SHA256()))
                sig_ok = True
            elif sig.get("alg") == "RSA" and registered_pub.get("rsa_pub_pem"):
                pub = RSA.import_key(registered_pub["rsa_pub_pem"].encode())
                from Crypto.Signature import pkcs1_15
                from Crypto.Hash import SHA256
                h = SHA256.new((plaintext or b"") + body.get("timestamp","").encode())
                pkcs1_15.new(pub).verify(h, b64d(sig["sig_b64"]))
                sig_ok = True
            elif "r" in sig and "s" in sig and registered_pub.get("elgamal_pub"):
                # elgamal verify (MD5-based H convention) — must match client
                el = registered_pub["elgamal_pub"]
                p = int(el["p"]); g = int(el["g"]); y = int(el["y"])
                r = int(sig["r"]); s = int(sig["s"])
                H = int.from_bytes(hashlib.md5((plaintext or b"") + body.get("timestamp","").encode()).digest(), "big") % (p-1)
                left = pow(g, H, p)
                right = (pow(y, r, p) * pow(r, s, p)) % p
                sig_ok = (left == right)
            else:
                sig_ok = False
    except Exception:
        sig_ok = False

    # store metadata + payload
    report_id = f"rep_{int(time.time())}_{doc_id}"
    reports = read_json_db(REPORTS_FILE, {})
    reports[report_id] = {
        "doctor_id": doc_id,
        "filename": body.get("filename"),
        "timestamp": body.get("timestamp"),
        "alg_report_enc": alg_report,
        "alg_key_enc": alg_key_enc,
        "enc_report": enc_report,
        "key_transport": key_transport,
        "sig": sig,
        "sig_ok": bool(sig_ok),
        "plaintext_path": None
    }
    # write plaintext to file if available
    out_dir = os.path.join(DATA_DIR, "reports")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    if plaintext is not None:
        out_path = os.path.join(out_dir, f"{report_id}_{body.get('filename')}")
        with open(out_path, "wb") as f:
            f.write(plaintext)
        reports[report_id]["plaintext_path"] = out_path
    write_json_db(REPORTS_FILE, reports)
    return {"status":"ok", "report_id": report_id, "sig_ok": sig_ok}

def handle_submit_expense(body):
    # store encrypted expense payload; server can sum using Paillier if available
    doc_id = body.get("doctor_id")
    alg = body.get("alg_expense_he", "Paillier")
    payload = body.get("cipher")
    if not doc_id or not payload:
        return {"status":"error","error":"missing fields"}
    expenses = read_json_db(EXPENSES_FILE, [])
    expenses.append({"doctor_id": doc_id, "alg": alg, "cipher": payload})
    write_json_db(EXPENSES_FILE, expenses)
    return {"status":"ok"}

def handle_audit_list_doctors(body):
    doctors = read_json_db(DOCTORS_FILE, {})
    doc_list = []
    for did, info in doctors.items():
        doc_list.append({"id": did, "sig_pub": info.get("sig_pub"), "dept_enc": info.get("dept_enc")})
    return {"status":"ok", "doctors": doc_list}

def handle_audit_sum_expenses(body):
    # only supports Paillier-summed expenses (best-effort)
    expenses = read_json_db(EXPENSES_FILE, [])
    total_enc = None
    count = 0
    for e in expenses:
        if e["alg"] == "Paillier":
            c = e["cipher"]
            enc = paillier.EncryptedNumber(PAILLIER_PUB, int(c["ciphertext"]), int(c["exponent"]))
            if total_enc is None:
                total_enc = enc
            else:
                total_enc += enc
            count += 1
    if total_enc is None:
        return {"status":"ok", "total_sum": 0, "count": count}
    total = PAILLIER_PRIV.decrypt(total_enc)
    return {"status":"ok", "total_sum": total, "count": count}

def handle_audit_list_reports(body):
    reports = read_json_db(REPORTS_FILE, {})
    out = []
    for rid, info in reports.items():
        out.append({"id": rid, "doctor_id": info["doctor_id"], "filename": info["filename"], "timestamp": info["timestamp"], "sig_ok": info.get("sig_ok")})
    return {"status":"ok", "reports": out}

def handle_audit_get_report_blob(body):
    report_id = body.get("report_id")
    reports = read_json_db(REPORTS_FILE, {})
    if report_id not in reports:
        return {"status":"error","error":"report not found"}
    return {"status":"ok", "report_data": reports[report_id]}

# ---------- Socket server ----------
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
            "audit_sum_expenses": handle_audit_sum_expenses,
            "audit_list_reports": handle_audit_list_reports,
            "audit_get_report_blob": handle_audit_get_report_blob,
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
                resp = self.HANDLER_MAP[role][action](body)
            else:
                resp = {"status":"error", "error": f"Unknown action '{action}' for role '{role}'"}
        except json.JSONDecodeError:
            resp = {"status":"error", "error": "Invalid JSON"}
        except Exception as e:
            resp = {"status":"error", "error": f"Internal server error: {e}"}
        try:
            self.wfile.write((json.dumps(resp) + "\n").encode('utf-8'))
        except BrokenPipeError:
            pass

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

# ---------- Auditor console ----------
def run_auditor_console():
    print("\n--- Auditor Console ---")
    while True:
        print("\n1. List doctors\n2. Sum expenses (Paillier)\n3. List reports\n4. View & attempt decrypt report\n0. Exit")
        c = input("Choice: ").strip()
        if c == "1":
            print(json.dumps(handle_audit_list_doctors({}), indent=2))
        elif c == "2":
            print(json.dumps(handle_audit_sum_expenses({}), indent=2))
        elif c == "3":
            print(json.dumps(handle_audit_list_reports({}), indent=2))
        elif c == "4":
            repid = input("Report ID: ").strip()
            resp = handle_audit_get_report_blob({"report_id": repid})
            print(json.dumps(resp, indent=2))
            if resp.get("status") == "ok":
                blob = resp["report_data"]
                # attempt local decryption if RSA-wrapped key present (auditor RSA)
                try:
                    key_transport = blob.get("key_transport", {})
                    if blob.get("alg_key_enc") == "RSA" and key_transport.get("enc_key_b64"):
                        rsa_priv = RSA.import_key(AUDITOR_RSA_PRIV_PEM.encode())
                        aes_key = PKCS1_OAEP.new(rsa_priv).decrypt(b64d(key_transport["enc_key_b64"]))
                        enc_report = blob.get("enc_report", {})
                        nonce = b64d(enc_report["nonce"])
                        ct = b64d(enc_report["ct"])
                        tag = b64d(enc_report["tag"])
                        plain = AES.new(aes_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
                        print("DECRYPTED CONTENT:\n", plain.decode('utf-8'))
                    else:
                        print("[auditor] Cannot auto-decrypt: key transport not RSA or missing.")
                except Exception as e:
                    print("[auditor] Decrypt failed:", e)
        elif c == "0":
            break
        else:
            print("Invalid choice.")

# ---------- START SERVER ----------
def start_server():
    print(f"[server] starting on {HOST}:{PORT}")
    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        run_auditor_console()
    finally:
        server.shutdown()
        server.server_close()

if __name__ == "__main__":
    start_server()
