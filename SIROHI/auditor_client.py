#!/usr/bin/env python3
"""
is_lab_complex_auditor_client.py

Auditor client for the privacy-preserving medical system.
- This is the *ONLY* client that can decrypt medical reports.
- It holds the Auditor's RSA Private Key.
- It performs local decryption and signature verification.
- It instructs the server to perform homomorphic operations
  and return the *final aggregate* results.
"""
import os
import json
import socket
import hashlib
import base64
from pathlib import Path
from getpass import getpass

# --- Pycryptodome Imports ---
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

# --- Cryptography Imports (for ECDSA) ---
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# --- Configuration ---
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5001
# Assumes server data dir is accessible, or key is provided
AUDITOR_RSA_PRIV_FILE = os.path.join("server_data_complex", "auditor_rsa_key.pem")
AUDITOR_RSA_PASS = "auditor_pass"  # Demo password
DECRYPTED_REPORTS_DIR = "auditor_decrypted_reports"


# --- Utility Functions ---

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))


def send_request(action, body):
    """Send JSON request to server as 'auditor' and receive response."""
    req = {"action": action, "role": "auditor", "body": body}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((SERVER_HOST, SERVER_PORT))
            sock.sendall((json.dumps(req) + "\n").encode('utf-8'))
            data = sock.recv(8192).decode('utf-8')  # Increased buffer
            return json.loads(data)
    except Exception as e:
        return {"status": "error", "error": f"Connection failed: {e}"}


# --- Auditor Functions ---

def load_auditor_key():
    """Load the Auditor's RSA private key."""
    try:
        key_pem = Path(AUDITOR_RSA_PRIV_FILE).read_bytes()
        key = RSA.import_key(key_pem, passphrase=AUDITOR_RSA_PASS)
        return key
    except Exception as e:
        print(f"[❌] FATAL: Could not load Auditor private key from {AUDITOR_RSA_PRIV_FILE}")
        print(f"   Error: {e}")
        print("   Make sure the server has run once to generate keys.")
        return None


def list_doctors():
    resp = send_request("audit_list_doctors", {})
    if resp.get("status") == "ok":
        print("\n--- Registered Doctors ---")
        for doc in resp.get("doctors", []):
            print(f"- ID: {doc['id']}")
    else:
        print(f"[❌] Error: {resp.get('error')}")


def search_doctors():
    keyword = input("Enter department keyword to search: ").strip().lower()
    if not keyword: return

    resp = send_request("audit_search_dept", {"keyword": keyword})
    if resp.get("status") == "ok":
        matches = resp.get("matches", [])
        print(f"\n--- Search Results for '{keyword}' ---")
        if not matches:
            print("No matches found.")
        for doc_id in matches:
            print(f"- Found Doctor ID: {doc_id}")
    else:
        print(f"[❌] Error: {resp.get('error')}")


def sum_expenses():
    print("\nRequesting homomorphic sum of all expenses from server...")
    resp = send_request("audit_sum_expenses", {})
    if resp.get("status") == "ok":
        print(f"\n--- Total Expenses (All Doctors) ---")
        print(f"  Total Amount: ${resp.get('total_sum')}")
        print(f"  Entry Count:   {resp.get('count')}")
    else:
        print(f"[❌] Error: {resp.get('error')}")


def audit_reports(auditor_rsa_key):
    # 1. Get list of reports
    list_resp = send_request("audit_list_reports", {})
    if list_resp.get("status") != "ok":
        print(f"[❌] Could not list reports: {list_resp.get('error')}")
        return

    reports = list_resp.get("reports", [])
    if not reports:
        print("\nNo reports found on server.")
        return

    print("\n--- Encrypted Reports on Server ---")
    for i, rep in enumerate(reports):
        print(f"  {i + 1}. ID: {rep['id']}")
        print(f"     File: {rep['file']}, Doctor: {rep['doc_id']}, TS: {rep['ts']}")

    try:
        choice = int(input("Select report # to audit/decrypt: ")) - 1
        report_to_audit = reports[choice]
    except (IndexError, ValueError):
        print("[❌] Invalid selection.")
        return

    print(f"\nAuditing Report ID: {report_to_audit['id']}...")

    # 2. Get the full encrypted blob for that report
    blob_resp = send_request("audit_get_report_blob", {"report_id": report_to_audit['id']})
    if blob_resp.get("status") != "ok":
        print(f"[❌] Could not fetch report blob: {blob_resp.get('error')}")
        return

    blob = blob_resp.get("report_data")

    # 3. Get the signing doctor's public key
    key_resp = send_request("get_doctor_pubkey", {"doctor_id": blob['doctor_id']})
    if key_resp.get("status") != "ok":
        print(f"[❌] Could not fetch doctor's pubkey: {key_resp.get('error')}")
        return

    try:
        doctor_ecdsa_pub = serialization.load_pem_public_key(
            key_resp['ecdsa_pub_pem'].encode('utf-8')
        )
    except Exception as e:
        print(f"[❌] Failed to parse doctor's ECDSA key: {e}")
        return

    # 4. Perform local decryption and verification
    try:
        # Step 4a: Decrypt AES key with Auditor's RSA Private Key
        cipher_rsa = PKCS1_OAEP.new(auditor_rsa_key)
        aes_key = cipher_rsa.decrypt(b64d(blob['encrypted_aes_key_b64']))

        # Step 4b: Decrypt Report with AES-GCM
        nonce = b64d(blob['aes_gcm_nonce_b64'])
        tag = b64d(blob['aes_gcm_tag_b64'])
        ciphertext = b64d(blob['aes_gcm_ciphertext_b64'])

        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag)
        report_hash = hashlib.sha256(plaintext_bytes).digest()

        print(f"\n[✅] Report decrypted successfully (AES-GCM).")

        # Step 4c: Verify ECDSA Signature
        signature = b64d(blob['ecdsa_signature_b64'])
        data_that_was_signed = report_hash + blob['timestamp'].encode('utf-8')

        doctor_ecdsa_pub.verify(
            signature,
            data_that_was_signed,
            ec.ECDSA(hashes.SHA256())
        )

        print(f"[✅] SIGNATURE IS VALID (ECDSA).")

        # 5. Save and show decrypted report
        print("-" * 30)
        print(f"DECRYPTED REPORT (from {blob['doctor_id']}):")
        print(plaintext_bytes.decode('utf-8'))
        print("-" * 30)

        os.makedirs(DECRYPTED_REPORTS_DIR, exist_ok=True)
        save_path = Path(DECRYPTED_REPORTS_DIR) / f"{report_to_audit['id']}.txt"
        save_path.write_bytes(plaintext_bytes)
        print(f"Decrypted report saved to: {save_path}")

    except (ValueError, InvalidSignature):
        print(f"[❌] AUDIT FAILED! SIGNATURE IS INVALID OR DATA TAMPERED.")
    except Exception as e:
        print(f"[❌] Audit failed during decryption: {e}")


# --- Main Menu ---

def main():
    print("--- Auditor Client ---")
    print("Loading Auditor credentials...")
    auditor_rsa_key = load_auditor_key()
    if not auditor_rsa_key:
        return

    while True:
        print("\n--- Auditor Client Menu ---")
        print("1. List Registered Doctors")
        print("2. Search Doctors by Department (Homomorphic)")
        print("3. Sum All Expenses (Homomorphic)")
        print("4. List & Audit Encrypted Reports (Local Decryption)")
        print("0. Exit")

        choice = input("Choice: ").strip()

        if choice == "1":
            list_doctors()
        elif choice == "2":
            search_doctors()
        elif choice == "3":
            sum_expenses()
        elif choice == "4":
            audit_reports(auditor_rsa_key)
        elif choice == "0":
            print("Exiting.")
            break
        else:
            print("[❌] Invalid choice.")


if __name__ == "__main__":
    main()