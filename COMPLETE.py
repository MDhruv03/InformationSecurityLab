#BASIC SHA RABIN ELGAMAL
import hashlib
import random, math
from random import randint
import time

# ---------- SHA-512 Hash ----------
def sha512_hash(message: str) -> str:
    """Return hex SHA-512 digest of a string."""
    return hashlib.sha512(message.encode()).hexdigest()

# ---------- Rabin Cryptosystem ----------
def rabin_keygen(bits=512):
    """Generate Rabin keys: n = p*q, p ≡ q ≡ 3 mod 4."""
    def prime_3mod4():
        while True:
            p = random.getrandbits(bits // 2)
            if p % 4 == 3 and pow(2, p - 1, p) == 1:
                return p
    p, q = prime_3mod4(), prime_3mod4()
    return (p, q, p * q)      # private: (p,q), public: n

def rabin_encrypt(message: str, n: int) -> int:
    m = int.from_bytes(message.encode(), 'big')
    return pow(m, 2, n)

def rabin_decrypt(cipher: int, p: int, q: int) -> str:
    # Chinese Remainder to find square roots
    mp = pow(cipher, (p + 1) // 4, p)
    mq = pow(cipher, (q + 1) // 4, q)
    # combine
    yp = pow(p, -1, q)
    yq = pow(q, -1, p)
    r1 = (yp * p * mq + yq * q * mp) % (p * q)
    r2 = (p * q - r1) % (p * q)
    r3 = (yp * p * (-mq) + yq * q * mp) % (p * q)
    r4 = (p * q - r3) % (p * q)
    for r in [r1, r2, r3, r4]:
        try:
            return r.to_bytes((r.bit_length() + 7) // 8, 'big').decode()
        except UnicodeDecodeError:
            continue
    raise ValueError("No valid plaintext root")

# ---------- ElGamal Digital Signature ----------
def elgamal_keygen(p: int, g: int):
    """Generate ElGamal keys given prime p and generator g."""
    x = randint(1, p - 2)          # private
    y = pow(g, x, p)               # public
    return (p, g, y, x)

def elgamal_sign(message: str, p: int, g: int, x: int) -> tuple:
    """Sign SHA-512 hash of message."""
    h = int(sha512_hash(message), 16)
    while True:
        k = randint(1, p - 2)
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return (r, s)

def elgamal_verify(message: str, sig: tuple, p: int, g: int, y: int) -> bool:
    """Verify ElGamal signature (r,s)."""
    r, s = sig
    if not (0 < r < p):
        return False
    h = int(sha512_hash(message), 16)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

# ---------- Auditor Log ----------
audit_log = []

def record_transaction(customer: str, merchant: str, hash_val: str, signature: tuple):
    """Append a transaction record for auditor."""
    audit_log.append({
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'merchant': merchant,
        'hash': hash_val,
        'signature': signature
    })

# ---------- Main Menu ----------
def main_menu():
    # Rabin keys
    p_rabin, q_rabin, n_rabin = rabin_keygen(512)
    # ElGamal keys (for demo we pick a small safe prime; replace with bigger if needed)
    p_elg = 30803
    g_elg = 2
    p, g, y, x = elgamal_keygen(p_elg, g_elg)

    customer_name = "Customer1"
    merchant_name = "Merchant1"

    encrypted_msg = None
    signature = None
    original_msg = None
    hash_msg = None

    while True:
        print("\n==== Finsecure Corp Menu ====")
        print("1. Customer: Encrypt + Hash + Sign")
        print("2. Merchant: Verify + Decrypt")
        print("3. Auditor: View Transaction Log")
        print("4. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            msg = input("Enter transaction message: ")
            original_msg = msg
            encrypted_msg = rabin_encrypt(msg, n_rabin)
            hash_msg = sha512_hash(msg)
            signature = elgamal_sign(msg, p, g, x)
            record_transaction(customer_name, merchant_name, hash_msg, signature)
            print("\n[Customer] Message encrypted & signed.")
            print("Ciphertext:", encrypted_msg)
            print("SHA512 Hash:", hash_msg)
            print("Signature (r,s):", signature)

        elif choice == "2":
            if not encrypted_msg:
                print("\n[Merchant] No message to verify/decrypt yet.")
                continue
            if elgamal_verify(original_msg, signature, p, g, y):
                print("\n[Merchant] Signature verified.")
                decrypted = rabin_decrypt(encrypted_msg, p_rabin, q_rabin)
                print("Decrypted Message:", decrypted)
            else:
                print("\n[Merchant] Signature verification failed!")

        elif choice == "3":
            print("\n[Auditor] Transaction Records:")
            for rec in audit_log:
                print(f"Time: {rec['time']}, Customer: {rec['customer']}, "
                      f"Merchant: {rec['merchant']}\n  Hash: {rec['hash']}\n  Signature: {rec['signature']}\n")

        elif choice == "4":
            print("Exiting...")
            break

        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main_menu()

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#SHA ECC ELGAMAL
import hashlib, math, time, base64
from random import randint
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

# ---------- SHA-512 Hash ----------
def sha512_hash(message: str) -> str:
    return hashlib.sha512(message.encode()).hexdigest()

# ---------- ECC Encryption / Decryption (ECIES style) ----------
def ecc_generate_key():
    """Generate a new ECC private key on P-256 curve."""
    return ECC.generate(curve="P-256")

def ecc_encrypt(plaintext: str, pubkey: ECC.EccKey) -> dict:
    """
    Encrypt using ephemeral ECDH + AES-GCM.
    Returns dict with ciphertext, nonce, tag, and ephemeral public key.
    """
    eph = ECC.generate(curve="P-256")
    shared = (pubkey.pointQ * eph.d).x
    shared_bytes = int(shared).to_bytes((shared.bit_length() + 7)//8, 'big')
    key = HKDF(shared_bytes, 32, b'', SHA512)[:16]   # AES-128
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "eph_pub": eph.public_key().export_key(format="PEM")
    }

def ecc_decrypt(enc_dict: dict, privkey: ECC.EccKey) -> str:
    eph_pub = ECC.import_key(enc_dict["eph_pub"])
    shared = (eph_pub.pointQ * privkey.d).x
    shared_bytes = int(shared).to_bytes((shared.bit_length() + 7)//8, 'big')
    key = HKDF(shared_bytes, 32, b'', SHA512)[:16]
    cipher = AES.new(key, AES.MODE_GCM,
                     nonce=base64.b64decode(enc_dict["nonce"]))
    pt = cipher.decrypt_and_verify(base64.b64decode(enc_dict["ciphertext"]),
                                   base64.b64decode(enc_dict["tag"]))
    return pt.decode()

# ---------- ElGamal Digital Signature ----------
def elgamal_keygen(p: int, g: int):
    x = randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, y, x)

def elgamal_sign(message: str, p: int, g: int, x: int) -> tuple:
    h = int(sha512_hash(message), 16)
    while True:
        k = randint(1, p - 2)
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return (r, s)

def elgamal_verify(message: str, sig: tuple, p: int, g: int, y: int) -> bool:
    r, s = sig
    if not (0 < r < p):
        return False
    h = int(sha512_hash(message), 16)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

# ---------- Auditor Log ----------
audit_log = []

def record_transaction(customer: str, merchant: str, hash_val: str, signature: tuple):
    audit_log.append({
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'merchant': merchant,
        'hash': hash_val,
        'signature': signature
    })

# ---------- Main Menu ----------
def main_menu():
    # ECC key pairs (one for sender, one for receiver)
    customer_priv = ecc_generate_key()
    merchant_priv = ecc_generate_key()
    merchant_pub = merchant_priv.public_key()

    # ElGamal keys for signatures
    p_elg = 30803
    g_elg = 2
    p, g, y, x = elgamal_keygen(p_elg, g_elg)

    customer_name = "Customer1"
    merchant_name = "Merchant1"

    enc_package = None
    signature = None
    original_msg = None
    hash_msg = None

    while True:
        print("\n==== Finsecure Corp (ECC Version) ====")
        print("1. Customer: Encrypt + Hash + Sign")
        print("2. Merchant: Verify + Decrypt")
        print("3. Auditor: View Transaction Log")
        print("4. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            msg = input("Enter transaction message: ")
            original_msg = msg
            enc_package = ecc_encrypt(msg, merchant_pub)
            hash_msg = sha512_hash(msg)
            signature = elgamal_sign(msg, p, g, x)
            record_transaction(customer_name, merchant_name, hash_msg, signature)
            print("\n[Customer] Message encrypted & signed.")
            print("Ciphertext:", enc_package["ciphertext"])
            print("SHA512 Hash:", hash_msg)
            print("Signature (r,s):", signature)

        elif choice == "2":
            if not enc_package:
                print("\n[Merchant] No message to verify/decrypt yet.")
                continue
            if elgamal_verify(original_msg, signature, p, g, y):
                print("\n[Merchant] Signature verified.")
                decrypted = ecc_decrypt(enc_package, merchant_priv)
                print("Decrypted Message:", decrypted)
            else:
                print("\n[Merchant] Signature verification failed!")

        elif choice == "3":
            print("\n[Auditor] Transaction Records:")
            for rec in audit_log:
                print(f"Time: {rec['time']}, Customer: {rec['customer']}, "
                      f"Merchant: {rec['merchant']}\n  Hash: {rec['hash']}\n  Signature: {rec['signature']}\n")

        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main_menu()
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#AES RSA HASH


---------------------------------------------------------------------------------------------------------------------------
#AES RSA
import time, base64
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

# ---------- AES Encryption / Decryption ----------
def aes_encrypt_bytes(data: bytes, key: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def aes_decrypt_bytes(enc: dict, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(enc["nonce"]))
    return cipher.decrypt_and_verify(
        base64.b64decode(enc["ciphertext"]),
        base64.b64decode(enc["tag"])
    )

# ---------- RSA Sign / Verify ----------
def rsa_generate(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

def rsa_sign_bytes(data: bytes, privkey: RSA.RsaKey) -> str:
    h = SHA512.new(data)
    sig = pkcs1_15.new(privkey).sign(h)
    return base64.b64encode(sig).decode()

def rsa_verify_bytes(data: bytes, signature_b64: str, pubkey: RSA.RsaKey) -> bool:
    h = SHA512.new(data)
    try:
        pkcs1_15.new(pubkey).verify(h, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False

# ---------- Auditor Log ----------
audit_log = []

def record_transaction(customer: str, merchant: str, hash_val: str, signature: str):
    audit_log.append({
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'merchant': merchant,
        'hash': hash_val,
        'signature': signature
    })

# ---------- Main Menu ----------
def main_menu():
    # Generate RSA keypairs
    customer_priv, customer_pub = rsa_generate()
    merchant_priv, merchant_pub = rsa_generate()

    # Shared AES key (for demo we keep it static in memory)
    aes_key = get_random_bytes(16)   # 128-bit

    customer_name = "Customer1"
    merchant_name = "Merchant1"

    encrypted_package = None
    signature = None
    original_pdf_bytes = None
    pdf_filename = None
    hash_msg = None

    while True:
        print("\n==== Secure PDF Transfer (AES + RSA) ====")
        print("1. Customer: Encrypt + Hash + Sign a PDF")
        print("2. Merchant: Verify + Decrypt PDF")
        print("3. Auditor: View Transaction Log")
        print("4. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            path = input("Enter path to PDF file: ").strip()
            if not Path(path).is_file():
                print("File not found.")
                continue
            original_pdf_bytes = Path(path).read_bytes()
            pdf_filename = Path(path).name

            # Encrypt
            encrypted_package = aes_encrypt_bytes(original_pdf_bytes, aes_key)

            # Hash & Sign
            h = SHA512.new(original_pdf_bytes).hexdigest()
            hash_msg = h
            signature = rsa_sign_bytes(original_pdf_bytes, customer_priv)

            record_transaction(customer_name, merchant_name, h, signature)

            print("\n[Customer] PDF encrypted & signed.")
            print("SHA512 Hash:", hash_msg)
            print("RSA Signature (base64):", signature[:60] + "...")

        elif choice == "2":
            if not encrypted_package:
                print("\n[Merchant] No PDF to verify/decrypt yet.")
                continue

            # Verify signature first
            if rsa_verify_bytes(original_pdf_bytes, signature, customer_pub):
                print("\n[Merchant] Signature verified.")
                decrypted_bytes = aes_decrypt_bytes(encrypted_package, aes_key)
                out = input(f"Output path for decrypted PDF (default: decrypted_{pdf_filename}): ").strip()
                if not out:
                    out = f"decrypted_{pdf_filename}"
                Path(out).write_bytes(decrypted_bytes)
                print(f"Decrypted PDF saved to: {out}")
            else:
                print("\n[Merchant] Signature verification failed!")

        elif choice == "3":
            print("\n[Auditor] Transaction Records:")
            for rec in audit_log:
                print(f"Time: {rec['time']}, Customer: {rec['customer']}, "
                      f"Merchant: {rec['merchant']}\n  Hash: {rec['hash']}\n  Signature: {rec['signature'][:60]}...\n")

        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main_menu()

------------------------------------------------------------------------------------------------------------------
-client
import os, socket, json, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

HOST, PORT = '127.0.0.1', 9100
KEY_DIR = './keys'

def rpc(obj):
    s = socket.socket()
    s.connect((HOST, PORT))
    s.sendall(json.dumps(obj).encode())
    resp = s.recv(50_000_000)
    s.close()
    return json.loads(resp.decode())

def load_priv(user):
    path = os.path.join(KEY_DIR, f"{user}_priv.pem")
    return RSA.import_key(open(path,'rb').read()) if os.path.exists(path) else None

def load_pub(user):
    path = os.path.join(KEY_DIR, f"{user}_pub.pem")
    return RSA.import_key(open(path,'rb').read()) if os.path.exists(path) else None

def register_user():
    u = input("Username: "); r = input("Role (patient/doctor/admin): ")
    pub = load_pub(u)
    if not pub: print("Generate keys first (keys_setup.py)."); return
    obj = {'cmd':'register_user','payload':{'username':u,'role':r,'pub_pem_b64':base64.b64encode(pub.export_key()).decode()}}
    print(rpc(obj))

def patient_upload():
    u = input("Patient username: ")
    priv = load_priv(u); pub = load_pub(u)
    if not priv or not pub: print("Missing keys."); return
    path = input("PDF path: ")
    data = open(path,'rb').read()
    aes_key = SHA512.new(data).digest()[:16]
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    sig = pkcs1_15.new(priv).sign(SHA512.new(ct))
    admin_pub = RSA.import_key(open(os.path.join(KEY_DIR,'admin_pub.pem'),'rb').read())
    aes_enc = PKCS1_OAEP.new(admin_pub, hashAlgo=SHA512).encrypt(aes_key)
    obj = {'cmd':'upload','payload':{
        'uploader':u,'role':'patient',
        'ct':base64.b64encode(ct).decode(),
        'nonce':base64.b64encode(cipher.nonce).decode(),
        'tag':base64.b64encode(tag).decode(),
        'sig':base64.b64encode(sig).decode(),
        'hash':base64.b64encode(SHA512.new(data).digest()).decode(),
        'aes_key_enc':base64.b64encode(aes_enc).decode(),
        'pubkey':base64.b64encode(pub.export_key()).decode()
    }}
    print(rpc(obj))

def list_packages():
    u = input("Your username: "); r = input("Your role: ")
    print(json.dumps(rpc({'cmd':'list','payload':{'requester':u,'role':r}}), indent=2))

def verify_signature():
    pid = int(input("Package id: "))
    print(json.dumps(rpc({'cmd':'verify_signature','payload':{'pkg_id':pid}}), indent=2))

def decrypt_pdf():
    u = input("Your username: "); r = input("Your role (doctor/admin): ")
    pid = int(input("Package id: "))
    resp = rpc({'cmd':'decrypt','payload':{'pkg_id':pid,'requester':u,'role':r}})
    if resp.get('status')=='ok':
        out = input("Output path for decrypted PDF: ")
        open(out,'wb').write(base64.b64decode(resp['plaintext_b64']))
        print("Saved to", out)
    else:
        print(resp)

def menu():
    while True:
        print("\n1) Register user on server")
        print("2) Patient: Upload PDF")
        print("3) List packages")
        print("4) Verify stored signature")
        print("5) Doctor/Admin: Decrypt PDF")
        print("6) Exit")
        ch = input("Choice: ")
        if ch=='1': register_user()
        elif ch=='2': patient_upload()
        elif ch=='3': list_packages()
        elif ch=='4': verify_signature()
        elif ch=='5': decrypt_pdf()
        else: break

if __name__ == "__main__":
    menu()
--------------------------------------------------------------------------------------------------------------------
-server
import socket, threading, json, base64, os, time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

HOST, PORT = '127.0.0.1', 9100
KEY_DIR = './keys'

# Load admin private key for decrypting AES keys
def load_admin_priv():
    path = os.path.join(KEY_DIR, 'admin_priv.pem')
    if not os.path.exists(path):
        raise FileNotFoundError("Run keys_setup.py first to create ./keys/admin_priv.pem")
    return RSA.import_key(open(path,'rb').read())

ADMIN_PRIV = load_admin_priv()

packages = {}       # pkg_id -> data
users = {}          # username -> {role, pub_pem_b64}
pkg_counter = 1
lock = threading.Lock()

def verify_signature(pub_pem_b64, data_bytes, sig_b64):
    pub = RSA.import_key(base64.b64decode(pub_pem_b64))
    sig = base64.b64decode(sig_b64)
    h = SHA512.new(data_bytes)
    try:
        pkcs1_15.new(pub).verify(h, sig)
        return True
    except Exception:
        return False

def handle_register(payload):
    u, r, pub = payload.get('username'), payload.get('role'), payload.get('pub_pem_b64')
    if not u or not r or not pub: return {'status':'error','msg':'bad args'}
    users[u] = {'role': r, 'pub_pem_b64': pub}
    return {'status':'ok'}

def handle_upload(payload):
    global pkg_counter
    need = ('uploader','role','ct','nonce','tag','sig','hash','aes_key_enc','pubkey')
    if not all(k in payload for k in need):
        return {'status':'error','msg':'missing fields'}
    if payload['role'] != 'patient':
        return {'status':'error','msg':'only patients can upload'}
    ct = base64.b64decode(payload['ct'])
    if not verify_signature(payload['pubkey'], ct, payload['sig']):
        return {'status':'error','msg':'signature invalid'}
    with lock:
        pid = pkg_counter; pkg_counter += 1
        packages[pid] = {**payload, 'id': pid, 'ts': time.time()}
    return {'status':'ok','pkg_id': pid}

def handle_list(payload):
    req, role = payload.get('requester'), payload.get('role')
    out = []
    for pid,p in packages.items():
        if role in ('admin','doctor') or p['uploader']==req:
            out.append({'id':pid,'uploader':p['uploader'],'ts':p['ts']})
    return {'status':'ok','packages':out}

def handle_verify(payload):
    pid = payload.get('pkg_id')
    if pid not in packages: return {'status':'error','msg':'not found'}
    p = packages[pid]
    ct = base64.b64decode(p['ct'])
    ok = verify_signature(p['pubkey'], ct, p['sig'])
    return {'status':'ok','valid':bool(ok)}

def handle_decrypt(payload):
    role = payload.get('role')
    if role not in ('admin','doctor'):
        return {'status':'error','msg':'unauthorized'}
    pid = payload.get('pkg_id')
    if pid not in packages: return {'status':'error','msg':'not found'}
    p = packages[pid]
    try:
        aes_key = PKCS1_OAEP.new(ADMIN_PRIV, hashAlgo=SHA512).decrypt(base64.b64decode(p['aes_key_enc']))
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=base64.b64decode(p['nonce']))
        pt = cipher.decrypt_and_verify(base64.b64decode(p['ct']), base64.b64decode(p['tag']))
        return {'status':'ok','plaintext_b64': base64.b64encode(pt).decode(), 'uploader': p['uploader']}
    except Exception as e:
        return {'status':'error','msg':'decrypt failed: '+str(e)}

handlers = {
    'register_user': handle_register,
    'upload': handle_upload,
    'list': handle_list,
    'verify_signature': handle_verify,
    'decrypt': handle_decrypt
}

def client_thread(conn):
    with conn:
        try:
            data = conn.recv(50_000_000)
            obj = json.loads(data.decode())
            cmd, payload = obj.get('cmd'), obj.get('payload',{})
            resp = handlers[cmd](payload) if cmd in handlers else {'status':'error','msg':'bad cmd'}
        except Exception as e:
            resp = {'status':'error','msg':str(e)}
        conn.sendall(json.dumps(resp).encode())

def main():
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[server] listening on {HOST}:{PORT}")
    while True:
        conn,_ = s.accept()
        threading.Thread(target=client_thread, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    main()
--------------------------------------------------------------------------------------------------------------------
import hashlib, random, math, time
from random import getrandbits

# ---------- SHA-512 Hash ----------
def sha512_hash(message: str) -> str:
    return hashlib.sha512(message.encode()).hexdigest()

# ---------- Rabin Key Generation (for encryption & signature) ----------
def rabin_keygen(bits=512):
    """Generate Rabin keys: n = p*q, p ≡ q ≡ 3 (mod 4)."""
    def prime_3mod4():
        while True:
            p = random.getrandbits(bits // 2)
            if p % 4 == 3 and pow(2, p - 1, p) == 1:
                return p
    p, q = prime_3mod4(), prime_3mod4()
    return p, q, p * q     # private (p,q), public n

# ---------- Rabin Encryption / Decryption ----------
def rabin_encrypt(message: str, n: int) -> int:
    m = int.from_bytes(message.encode(), 'big')
    return pow(m, 2, n)

def rabin_decrypt(cipher: int, p: int, q: int) -> str:
    mp = pow(cipher, (p + 1) // 4, p)
    mq = pow(cipher, (q + 1) // 4, q)
    yp = pow(p, -1, q)
    yq = pow(q, -1, p)
    r1 = (yp * p * mq + yq * q * mp) % (p * q)
    r2 = (p * q - r1) % (p * q)
    r3 = (yp * p * (-mq) + yq * q * mp) % (p * q)
    r4 = (p * q - r3) % (p * q)
    for r in [r1, r2, r3, r4]:
        try:
            return r.to_bytes((r.bit_length() + 7) // 8, 'big').decode()
        except UnicodeDecodeError:
            continue
    raise ValueError("No valid plaintext root")

# ---------- Rabin Digital Signature ----------
def rabin_sign(message: str, p: int, q: int) -> int:
    """
    Rabin signature: sign the SHA-512 hash of the message.
    Signature = sqrt(hash mod n), using CRT to find a valid root.
    """
    n = p * q
    h = int(sha512_hash(message), 16) % n
    # ensure h is a quadratic residue mod p and q
    # simple rehash until condition holds
    while pow(h, (p - 1) // 2, p) != 1 or pow(h, (q - 1) // 2, q) != 1:
        h = int(hashlib.sha512((str(h)).encode()).hexdigest(), 16) % n
    sp = pow(h, (p + 1) // 4, p)
    sq = pow(h, (q + 1) // 4, q)
    yp = pow(p, -1, q)
    yq = pow(q, -1, p)
    sig = (yp * p * sq + yq * q * sp) % n
    return sig

def rabin_verify(message: str, signature: int, n: int) -> bool:
    h = int(sha512_hash(message), 16) % n
    return pow(signature, 2, n) == h

# ---------- Auditor Log ----------
audit_log = []

def record_transaction(customer: str, merchant: str, hash_val: str, signature: int):
    audit_log.append({
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'merchant': merchant,
        'hash': hash_val,
        'signature': signature
    })

# ---------- Main Menu ----------
def main_menu():
    p_rabin, q_rabin, n_rabin = rabin_keygen(512)

    customer_name = "Customer1"
    merchant_name = "Merchant1"

    encrypted_msg = None
    signature = None
    original_msg = None
    hash_msg = None

    while True:
        print("\n==== Finsecure Corp Menu ====")
        print("1. Customer: Encrypt + Hash + Rabin Sign")
        print("2. Merchant: Verify Rabin Signature + Decrypt")
        print("3. Auditor: View Transaction Log")
        print("4. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            msg = input("Enter transaction message: ")
            original_msg = msg
            encrypted_msg = rabin_encrypt(msg, n_rabin)
            hash_msg = sha512_hash(msg)
            signature = rabin_sign(msg, p_rabin, q_rabin)
            record_transaction(customer_name, merchant_name, hash_msg, signature)
            print("\n[Customer] Message encrypted & signed.")
            print("Ciphertext:", encrypted_msg)
            print("SHA512 Hash:", hash_msg)
            print("Rabin Signature:", signature)

        elif choice == "2":
            if encrypted_msg is None:
                print("\n[Merchant] No message to verify/decrypt yet.")
                continue
            if rabin_verify(original_msg, signature, p_rabin * q_rabin):
                print("\n[Merchant] ✅ Rabin signature verified.")
                decrypted = rabin_decrypt(encrypted_msg, p_rabin, q_rabin)
                print("Decrypted Message:", decrypted)
            else:
                print("\n[Merchant] ❌ Signature verification failed!")

        elif choice == "3":
            print("\n[Auditor] Transaction Records:")
            for rec in audit_log:
                print(f"Time: {rec['time']}, Customer: {rec['customer']}, "
                      f"Merchant: {rec['merchant']}\n  Hash: {rec['hash']}\n  Signature: {rec['signature']}\n")

        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main_menu()
-------------------------------------------------------------------------------------------------------------------
-client
import socket, json, base64, math, hashlib
from random import randint
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import HKDF

# ---------- Crypto helpers ----------
def sha512_hash(m: str) -> str:
    return hashlib.sha512(m.encode()).hexdigest()

def ecc_encrypt(plaintext: str, pubkey_pem: str) -> dict:
    """
    Accepts a one-line PEM from the user and reformats it
    into the proper multi-line PEM before importing.
    """
    # If the key is a single line, reinsert newlines after the header and before the footer
    if "-----BEGIN PUBLIC KEY-----" in pubkey_pem and "-----END PUBLIC KEY-----" in pubkey_pem:
        body = pubkey_pem.replace("-----BEGIN PUBLIC KEY-----", "") \
                         .replace("-----END PUBLIC KEY-----", "") \
                         .replace(" ", "").replace("\n", "")
        pubkey_pem = "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n"

    pubkey = ECC.import_key(pubkey_pem)
    eph = ECC.generate(curve="P-256")
    shared = (pubkey.pointQ * eph.d).x
    # ✅ FIX: convert to native int before using bit_length
    shared_int = int(shared)
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, 'big')
    key = HKDF(shared_bytes, 32, b'', SHA512)[:16]
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "eph_pub": eph.public_key().export_key(format="PEM")
    }

def elgamal_keygen(p: int, g: int):
    x = randint(1, p-2)
    y = pow(g, x, p)
    return p, g, y, x

def elgamal_sign(message: str, p: int, g: int, x: int) -> tuple:
    h = int(sha512_hash(message), 16)
    while True:
        k = randint(1, p-2)
        if math.gcd(k, p-1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x * r) * pow(k, -1, p-1)) % (p-1)
    return (r, s)

# ---------- Client main ----------
HOST, PORT = '127.0.0.1', 9009

MERCHANT_PUB_PEM = input("Paste the merchant ECC public key PEM as one line: ")

# ElGamal keys for signing
p_elg = 30803
g_elg = 2
p, g, y, x = elgamal_keygen(p_elg, g_elg)

customer_name = input("Enter your name: ")
msg = input("Enter transaction message: ")

enc_pkg  = ecc_encrypt(msg, MERCHANT_PUB_PEM)
sig      = elgamal_sign(msg, p, g, x)
hash_msg = sha512_hash(msg)

payload = {
    "customer": customer_name,
    "enc_package": enc_pkg,
    "signature": sig,
    "hash": hash_msg,
    "p": p,
    "g": g,
    "y": y
}

with socket.socket() as s:
    s.connect((HOST, PORT))
    s.sendall(json.dumps(payload).encode())
    print("[Client] ✅ Sent encrypted + signed message.")
    resp = s.recv(4096)
    print("[Client] Server response:", resp.decode())
---------------------------------------------------------------------------------------------------------------------
import socket, json, time, base64, hashlib
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512

# ---------- ECC Helpers ----------
def ecc_generate_key():
    """Generate a P-256 key pair for the merchant."""
    return ECC.generate(curve="P-256")

def ecc_decrypt(enc_dict, privkey):
    """Decrypt AES-GCM ciphertext using shared ECDH key."""
    eph_pub = ECC.import_key(enc_dict["eph_pub"])
    shared = (eph_pub.pointQ * privkey.d).x
    # convert IntegerCustom to native int before bit_length
    shared_int = int(shared)
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, 'big')
    key = HKDF(shared_bytes, 32, b'', SHA512)[:16]
    cipher = AES.new(key, AES.MODE_GCM,
                     nonce=base64.b64decode(enc_dict["nonce"]))
    pt = cipher.decrypt_and_verify(base64.b64decode(enc_dict["ciphertext"]),
                                   base64.b64decode(enc_dict["tag"]))
    return pt.decode()

# ---------- ElGamal Verify ----------
def elgamal_verify(message, sig, p, g, y):
    r, s = sig
    if not (0 < r < p):
        return False
    h = int(hashlib.sha512(message.encode()).hexdigest(), 16)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

# ---------- Server Setup ----------
HOST, PORT = '127.0.0.1', 9009

merchant_priv = ecc_generate_key()
merchant_pub_pem = merchant_priv.public_key().export_key(format="PEM")

print("[Server] Give this public key to the client:\n")
print(merchant_pub_pem)

audit_log = []

def handle_client(conn):
    """Process a single client connection."""
    try:
        data = conn.recv(100000).decode()
        obj = json.loads(data)
        enc_pkg = obj['enc_package']
        signature = tuple(obj['signature'])
        msg_hash  = obj['hash']
        p, g, y   = obj['p'], obj['g'], obj['y']

        plaintext = ecc_decrypt(enc_pkg, merchant_priv)
        ok = elgamal_verify(plaintext, signature, p, g, y)

        audit_log.append({
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'customer': obj['customer'],
            'hash': msg_hash,
            'signature': signature,
            'verified': ok
        })

        if ok:
            print(f"[Server] ✅ Verified message from {obj['customer']}: {plaintext}")
            conn.sendall(b"Signature OK and message decrypted.")
        else:
            print("[Server] ❌ Signature verification failed!")
            conn.sendall(b"Signature verification failed.")
    except Exception as e:
        print("[Server] Error handling client:", e)
        conn.sendall(b"Server error.")
    finally:
        conn.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Important: allow quick restart without 'address already in use'
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[Server] Listening on {HOST}:{PORT}")
    try:
        while True:
            c, addr = s.accept()
            print(f"[Server] Connection from {addr}")
            handle_client(c)
    finally:
        s.close()

if __name__ == "__main__":
    main()
------------------------------------------------------------------------------------------------------------------
import hashlib, random, time
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA512

# ---------- SHA-512 Hash ----------
def sha512_hash(message: str) -> str:
    return hashlib.sha512(message.encode()).hexdigest()

# ---------- Rabin Crypto (unchanged) ----------
def rabin_keygen(bits=512):
    def prime_3mod4():
        while True:
            p = random.getrandbits(bits // 2)
            if p % 4 == 3 and pow(2, p - 1, p) == 1:
                return p
    p, q = prime_3mod4(), prime_3mod4()
    return p, q, p * q

def rabin_encrypt(message: str, n: int) -> int:
    m = int.from_bytes(message.encode(), 'big')
    return pow(m, 2, n)

def rabin_decrypt(cipher: int, p: int, q: int) -> str:
    mp = pow(cipher, (p + 1)//4, p)
    mq = pow(cipher, (q + 1)//4, q)
    yp = pow(p, -1, q)
    yq = pow(q, -1, p)
    r1 = (yp*p*mq + yq*q*mp) % (p*q)
    r2 = (p*q - r1) % (p*q)
    r3 = (yp*p*(-mq) + yq*q*mp) % (p*q)
    r4 = (p*q - r3) % (p*q)
    for r in [r1,r2,r3,r4]:
        try:
            return r.to_bytes((r.bit_length()+7)//8,'big').decode()
        except UnicodeDecodeError:
            continue
    raise ValueError("No valid plaintext root")

# ---------- Diffie-Hellman style Signature (DSA) ----------
def dsa_keypair(bits=2048):
    """Generate a DSA key pair (same math as Diffie-Hellman)."""
    key = DSA.generate(bits)
    return key, key.publickey()

def dsa_sign(message: str, priv_key: DSA.DsaKey) -> bytes:
    h = SHA512.new(message.encode())
    signer = DSS.new(priv_key, 'fips-186-3')
    return signer.sign(h)

def dsa_verify(message: str, signature: bytes, pub_key: DSA.DsaKey) -> bool:
    h = SHA512.new(message.encode())
    verifier = DSS.new(pub_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

# ---------- Auditor Log ----------
audit_log = []

def record_transaction(customer, merchant, hash_val, signature):
    audit_log.append({
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'merchant': merchant,
        'hash': hash_val,
        'signature': signature.hex()
    })

# ---------- Main Menu ----------
def main_menu():
    # Keys
    p_rabin, q_rabin, n_rabin = rabin_keygen(512)
    dsa_priv, dsa_pub = dsa_keypair()

    customer_name = "Customer1"
    merchant_name = "Merchant1"

    encrypted_msg = None
    signature = None
    original_msg = None
    hash_msg = None

    while True:
        print("\n==== Finsecure Corp Menu ====")
        print("1. Customer: Encrypt + Hash + DSA Sign")
        print("2. Merchant: Verify DSA Signature + Decrypt")
        print("3. Auditor: View Transaction Log")
        print("4. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            msg = input("Enter transaction message: ")
            original_msg = msg
            encrypted_msg = rabin_encrypt(msg, n_rabin)
            hash_msg = sha512_hash(msg)
            signature = dsa_sign(msg, dsa_priv)
            record_transaction(customer_name, merchant_name, hash_msg, signature)
            print("\n[Customer] Message encrypted & signed.")
            print("Ciphertext:", encrypted_msg)
            print("SHA512 Hash:", hash_msg)
            print("DSA Signature (hex):", signature.hex())

        elif choice == "2":
            if encrypted_msg is None:
                print("\n[Merchant] No message to verify/decrypt yet.")
                continue
            if dsa_verify(original_msg, signature, dsa_pub):
                print("\n[Merchant] ✅ DSA signature verified.")
                decrypted = rabin_decrypt(encrypted_msg, p_rabin, q_rabin)
                print("Decrypted Message:", decrypted)
            else:
                print("\n[Merchant] ❌ Signature verification failed!")

        elif choice == "3":
            print("\n[Auditor] Transaction Records:")
            for rec in audit_log:
                print(f"Time: {rec['time']}, Customer: {rec['customer']}, "
                      f"Merchant: {rec['merchant']}\n  Hash: {rec['hash']}\n  Signature: {rec['signature']}\n")

        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main_menu()
-------------------------------------------------------------------------------------------------------------------
import hashlib, math, time, base64
from random import randint
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

# ---------- MD5 Hash ----------
def md5_hash(message: str) -> str:
    """Return hex MD5 digest of a string."""
    return hashlib.md5(message.encode()).hexdigest()

# ---------- ECC Encryption / Decryption (ECIES style) ----------
def ecc_generate_key():
    """Generate a new ECC private key on P-256 curve."""
    return ECC.generate(curve="P-256")

def ecc_encrypt(plaintext: str, pubkey: ECC.EccKey) -> dict:
    """Encrypt using ephemeral ECDH + AES-GCM."""
    eph = ECC.generate(curve="P-256")
    shared = (pubkey.pointQ * eph.d).x
    shared_bytes = int(shared).to_bytes((shared.bit_length() + 7)//8, 'big')
    # HKDF can still use SHA512 internally to derive key, that’s fine
    key = HKDF(shared_bytes, 32, b'', hashlib.sha512)[:16]   # AES-128 key
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "eph_pub": eph.public_key().export_key(format="PEM")
    }

def ecc_decrypt(enc_dict: dict, privkey: ECC.EccKey) -> str:
    eph_pub = ECC.import_key(enc_dict["eph_pub"])
    shared = (eph_pub.pointQ * privkey.d).x
    shared_bytes = int(shared).to_bytes((shared.bit_length() + 7)//8, 'big')
    key = HKDF(shared_bytes, 32, b'', hashlib.sha512)[:16]
    cipher = AES.new(key, AES.MODE_GCM,
                     nonce=base64.b64decode(enc_dict["nonce"]))
    pt = cipher.decrypt_and_verify(base64.b64decode(enc_dict["ciphertext"]),
                                   base64.b64decode(enc_dict["tag"]))
    return pt.decode()

# ---------- ElGamal Digital Signature (hash now MD5) ----------
def elgamal_keygen(p: int, g: int):
    x = randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, y, x)

def elgamal_sign(message: str, p: int, g: int, x: int) -> tuple:
    h = int(md5_hash(message), 16)     # use MD5 for signing
    while True:
        k = randint(1, p - 2)
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return (r, s)

def elgamal_verify(message: str, sig: tuple, p: int, g: int, y: int) -> bool:
    r, s = sig
    if not (0 < r < p):
        return False
    h = int(md5_hash(message), 16)     # verify with MD5
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

# ---------- Auditor Log ----------
audit_log = []

def record_transaction(customer: str, merchant: str, hash_val: str, signature: tuple):
    audit_log.append({
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'merchant': merchant,
        'hash': hash_val,
        'signature': signature
    })

# ---------- Main Menu ----------
def main_menu():
    customer_priv = ecc_generate_key()
    merchant_priv = ecc_generate_key()
    merchant_pub = merchant_priv.public_key()

    p_elg = 30803
    g_elg = 2
    p, g, y, x = elgamal_keygen(p_elg, g_elg)

    customer_name = "Customer1"
    merchant_name = "Merchant1"

    enc_package = None
    signature = None
    original_msg = None
    hash_msg = None

    while True:
        print("\n==== Finsecure Corp (ECC + MD5) ====")
        print("1. Customer: Encrypt + MD5 Hash + Sign")
        print("2. Merchant: Verify + Decrypt")
        print("3. Auditor: View Transaction Log")
        print("4. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            msg = input("Enter transaction message: ")
            original_msg = msg
            enc_package = ecc_encrypt(msg, merchant_pub)
            hash_msg = md5_hash(msg)
            signature = elgamal_sign(msg, p, g, x)
            record_transaction(customer_name, merchant_name, hash_msg, signature)
            print("\n[Customer] Message encrypted & signed.")
            print("Ciphertext:", enc_package["ciphertext"])
            print("MD5 Hash:", hash_msg)
            print("Signature (r,s):", signature)

        elif choice == "2":
            if not enc_package:
                print("\n[Merchant] No message to verify/decrypt yet.")
                continue
            if elgamal_verify(original_msg, signature, p, g, y):
                print("\n[Merchant] Signature verified.")
                decrypted = ecc_decrypt(enc_package, merchant_priv)
                print("Decrypted Message:", decrypted)
            else:
                print("\n[Merchant] Signature verification failed!")

        elif choice == "3":
            print("\n[Auditor] Transaction Records:")
            for rec in audit_log:
                print(f"Time: {rec['time']}, Customer: {rec['customer']}, "
                      f"Merchant: {rec['merchant']}\n  MD5 Hash: {rec['hash']}\n  Signature: {rec['signature']}\n")

        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main_menu()
------------------------------------------------------------------------------------------------------------------
import hashlib, math, time, base64
from random import randint
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

# ---------- SHA-1 Hash ----------
def sha1_hash(message: str) -> str:
    """Return hex SHA-1 digest of a string."""
    return hashlib.sha1(message.encode()).hexdigest()

# ---------- ECC Encryption / Decryption (ECIES style) ----------
def ecc_generate_key():
    """Generate a new ECC private key on P-256 curve."""
    return ECC.generate(curve="P-256")

def ecc_encrypt(plaintext: str, pubkey: ECC.EccKey) -> dict:
    """
    Encrypt using ephemeral ECDH + AES-GCM.
    Returns dict with ciphertext, nonce, tag, and ephemeral public key.
    """
    eph = ECC.generate(curve="P-256")
    shared = (pubkey.pointQ * eph.d).x
    shared_bytes = int(shared).to_bytes((shared.bit_length() + 7)//8, 'big')
    # HKDF can still use SHA-512 internally for key derivation
    key = HKDF(shared_bytes, 32, b'', hashlib.sha512)[:16]   # AES-128
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "eph_pub": eph.public_key().export_key(format="PEM")
    }

def ecc_decrypt(enc_dict: dict, privkey: ECC.EccKey) -> str:
    eph_pub = ECC.import_key(enc_dict["eph_pub"])
    shared = (eph_pub.pointQ * privkey.d).x
    shared_bytes = int(shared).to_bytes((shared.bit_length() + 7)//8, 'big')
    key = HKDF(shared_bytes, 32, b'', hashlib.sha512)[:16]
    cipher = AES.new(key, AES.MODE_GCM,
                     nonce=base64.b64decode(enc_dict["nonce"]))
    pt = cipher.decrypt_and_verify(base64.b64decode(enc_dict["ciphertext"]),
                                   base64.b64decode(enc_dict["tag"]))
    return pt.decode()

# ---------- ElGamal Digital Signature (now using SHA-1) ----------
def elgamal_keygen(p: int, g: int):
    x = randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, y, x)

def elgamal_sign(message: str, p: int, g: int, x: int) -> tuple:
    h = int(sha1_hash(message), 16)     # Use SHA-1 for signing
    while True:
        k = randint(1, p - 2)
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return (r, s)

def elgamal_verify(message: str, sig: tuple, p: int, g: int, y: int) -> bool:
    r, s = sig
    if not (0 < r < p):
        return False
    h = int(sha1_hash(message), 16)     # Verify with SHA-1
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

# ---------- Auditor Log ----------
audit_log = []

def record_transaction(customer: str, merchant: str, hash_val: str, signature: tuple):
    audit_log.append({
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'merchant': merchant,
        'hash': hash_val,
        'signature': signature
    })

# ---------- Main Menu ----------
def main_menu():
    # ECC key pairs (one for sender, one for receiver)
    customer_priv = ecc_generate_key()
    merchant_priv = ecc_generate_key()
    merchant_pub = merchant_priv.public_key()

    # ElGamal keys for signatures
    p_elg = 30803
    g_elg = 2
    p, g, y, x = elgamal_keygen(p_elg, g_elg)

    customer_name = "Customer1"
    merchant_name = "Merchant1"

    enc_package = None
    signature = None
    original_msg = None
    hash_msg = None

    while True:
        print("\n==== Finsecure Corp (ECC + SHA-1) ====")
        print("1. Customer: Encrypt + SHA-1 Hash + Sign")
        print("2. Merchant: Verify + Decrypt")
        print("3. Auditor: View Transaction Log")
        print("4. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            msg = input("Enter transaction message: ")
            original_msg = msg
            enc_package = ecc_encrypt(msg, merchant_pub)
            hash_msg = sha1_hash(msg)
            signature = elgamal_sign(msg, p, g, x)
            record_transaction(customer_name, merchant_name, hash_msg, signature)
            print("\n[Customer] Message encrypted & signed.")
            print("Ciphertext:", enc_package["ciphertext"])
            print("SHA-1 Hash:", hash_msg)
            print("Signature (r,s):", signature)

        elif choice == "2":
            if not enc_package:
                print("\n[Merchant] No message to verify/decrypt yet.")
                continue
            if elgamal_verify(original_msg, signature, p, g, y):
                print("\n[Merchant] Signature verified.")
                decrypted = ecc_decrypt(enc_package, merchant_priv)
                print("Decrypted Message:", decrypted)
            else:
                print("\n[Merchant] Signature verification failed!")

        elif choice == "3":
            print("\n[Auditor] Transaction Records:")
            for rec in audit_log:
                print(f"Time: {rec['time']}, Customer: {rec['customer']}, "
                      f"Merchant: {rec['merchant']}\n  SHA-1 Hash: {rec['hash']}\n  Signature: {rec['signature']}\n")

        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main_menu()
-------------------------------------------------------------------------------------------------------------------------

"""
pdf_secure_transfer.py

Single-file, menu-driven demo that:
- Reads a PDF file (or any file) as bytes
- Generates AES-128-GCM session key and encrypts file bytes
- Optionally RSA-encrypts the AES key for the recipient (OAEP)
- Computes SHA-512 hash and signs the hash with RSA (PKCS#1 v1.5)
- Verifies signature and decrypts on recipient side
- Maintains an auditor log (in-memory and optionally saved to audit_log.json)

Dependencies: pycryptodome
    pip install pycryptodome

Usage: python3 pdf_secure_transfer.py

This script is educational/demo only. Do NOT use in production without careful security review.
"""

import os
import json
import time
import base64
from getpass import getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

AUDIT_LOG_FILE = "audit_log.json"
KEYS_DIR = "keys"
PACKAGE_DIR = "packages"

os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(PACKAGE_DIR, exist_ok=True)

# ---------- Helpers ----------

def save_pem(key: RSA.RsaKey, path: str, passphrase: str = None):
    if passphrase:
        pem = key.export_key(format='PEM', passphrase=passphrase, pkcs=8)
    else:
        pem = key.export_key()
    with open(path, 'wb') as f:
        f.write(pem)


def load_pem(path: str, passphrase: str = None) -> RSA.RsaKey:
    with open(path, 'rb') as f:
        data = f.read()
    return RSA.import_key(data, passphrase=passphrase)


# ---------- AES (bytes) ----------

def aes_encrypt_bytes(plaintext_bytes: bytes, key: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }


def aes_decrypt_bytes(enc: dict, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(enc["nonce"]))
    pt = cipher.decrypt_and_verify(
        base64.b64decode(enc["ciphertext"]),
        base64.b64decode(enc["tag"])
    )
    return pt


# ---------- RSA (key wrap / sign) ----------

def rsa_generate(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()


def rsa_wrap_key(aes_key: bytes, recipient_pub: RSA.RsaKey) -> str:
    cipher_rsa = PKCS1_OAEP.new(recipient_pub)
    enc_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(enc_key).decode()


def rsa_unwrap_key(enc_key_b64: str, recipient_priv: RSA.RsaKey) -> bytes:
    cipher_rsa = PKCS1_OAEP.new(recipient_priv)
    return cipher_rsa.decrypt(base64.b64decode(enc_key_b64))


def rsa_sign_bytes(message_bytes: bytes, privkey: RSA.RsaKey) -> str:
    h = SHA512.new(message_bytes)
    sig = pkcs1_15.new(privkey).sign(h)
    return base64.b64encode(sig).decode()


def rsa_verify_bytes(message_bytes: bytes, signature_b64: str, pubkey: RSA.RsaKey) -> bool:
    h = SHA512.new(message_bytes)
    try:
        pkcs1_15.new(pubkey).verify(h, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False


# ---------- Auditor Log ----------

def load_audit_log():
    if os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, 'r') as f:
            return json.load(f)
    return []


def save_audit_log(log):
    with open(AUDIT_LOG_FILE, 'w') as f:
        json.dump(log, f, indent=2)


audit_log = load_audit_log()


def record_transaction(customer: str, merchant: str, filename: str, hash_val: str, signature: str, package_file: str):
    rec = {
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'merchant': merchant,
        'file': filename,
        'hash': hash_val,
        'signature': signature,
        'package': package_file
    }
    audit_log.append(rec)
    save_audit_log(audit_log)


# ---------- File helpers ----------

def read_file_bytes(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def write_file_bytes(path: str, data: bytes):
    with open(path, 'wb') as f:
        f.write(data)


# ---------- Menu Actions ----------

def action_generate_keys(name_prefix: str = "user"):
    bits = 2048
    priv, pub = rsa_generate(bits)
    priv_path = os.path.join(KEYS_DIR, f"{name_prefix}_priv.pem")
    pub_path = os.path.join(KEYS_DIR, f"{name_prefix}_pub.pem")
    save_pem(priv, priv_path)
    save_pem(pub, pub_path)
    print(f"Generated keys: {priv_path}, {pub_path}")


def action_encrypt_and_sign():
    print("\n--- Customer: Encrypt & Sign PDF ---")
    file_path = input("Path to PDF (or any file) to encrypt: ").strip()
    if not os.path.exists(file_path):
        print("File not found.")
        return
    customer_priv_path = input("Path to customer's private PEM (e.g. keys/customer_priv.pem): ").strip()
    recipient_pub_path = input("Path to recipient's public PEM (merchant) (e.g. keys/merchant_pub.pem): ").strip()
    if not (os.path.exists(customer_priv_path) and os.path.exists(recipient_pub_path)):
        print("Key file(s) missing.")
        return

    customer_priv = load_pem(customer_priv_path)
    recipient_pub = load_pem(recipient_pub_path)

    file_bytes = read_file_bytes(file_path)

    # AES session key
    aes_key = get_random_bytes(16)  # 128-bit

    enc_package = aes_encrypt_bytes(file_bytes, aes_key)

    # Wrap AES key with recipient's RSA public key so only recipient can unwrap
    wrapped_key_b64 = rsa_wrap_key(aes_key, recipient_pub)

    # Compute hash of plaintext (or ciphertext). We'll hash ciphertext for demonstration.
    hash_val = SHA512.new(base64.b64decode(enc_package['ciphertext'])).hexdigest()

    # Sign the ciphertext hash (or ciphertext bytes) with customer's private key
    signature_b64 = rsa_sign_bytes(base64.b64decode(enc_package['ciphertext']), customer_priv)

    # Save package JSON
    pkg = {
        'enc': enc_package,
        'wrapped_key': wrapped_key_b64,
        'signature': signature_b64,
        'orig_filename': os.path.basename(file_path)
    }
    pkg_filename = f"pkg_{int(time.time())}_{os.path.basename(file_path)}.json"
    pkg_path = os.path.join(PACKAGE_DIR, pkg_filename)
    with open(pkg_path, 'w') as f:
        json.dump(pkg, f)

    # Record in audit log
    record_transaction(os.path.basename(customer_priv_path), os.path.basename(recipient_pub_path), os.path.basename(file_path), hash_val, signature_b64, pkg_path)

    print(f"Package saved to: {pkg_path}")
    print("Encryption + signature complete.")


def action_verify_and_decrypt():
    print("\n--- Merchant: Verify & Decrypt ---")
    pkg_path = input("Path to package JSON (in packages/) : ").strip()
    if not os.path.exists(pkg_path):
        print("Package not found.")
        return
    merchant_priv_path = input("Path to merchant's private PEM (keys/merchant_priv.pem): ").strip()
    customer_pub_path = input("Path to customer's public PEM (keys/customer_pub.pem): ").strip()
    if not (os.path.exists(merchant_priv_path) and os.path.exists(customer_pub_path)):
        print("Key file(s) missing.")
        return

    merchant_priv = load_pem(merchant_priv_path)
    customer_pub = load_pem(customer_pub_path)

    with open(pkg_path, 'r') as f:
        pkg = json.load(f)

    enc_package = pkg['enc']
    wrapped_key = pkg['wrapped_key']
    signature_b64 = pkg['signature']
    orig_filename = pkg.get('orig_filename', 'decrypted.bin')

    # Unwrap AES key
    try:
        aes_key = rsa_unwrap_key(wrapped_key, merchant_priv)
    except Exception as e:
        print("Failed to unwrap AES key:", e)
        return

    # Verify signature (we verify over ciphertext bytes)
    ct_bytes = base64.b64decode(enc_package['ciphertext'])
    if rsa_verify_bytes(ct_bytes, signature_b64, customer_pub):
        print("Signature verified successfully.")
    else:
        print("Signature verification FAILED!")
        return

    # Decrypt
    try:
        plaintext_bytes = aes_decrypt_bytes(enc_package, aes_key)
    except Exception as e:
        print("AES decryption failed:", e)
        return

    out_path = os.path.join(PACKAGE_DIR, f"decrypted_{orig_filename}")
    write_file_bytes(out_path, plaintext_bytes)
    print(f"Decrypted file written to: {out_path}")


def action_audit_log():
    print("\n--- Auditor: Transaction Log ---")
    for rec in audit_log:
        print(f"Time: {rec['time']}, CustomerKey: {rec['customer']}, MerchantKey: {rec['merchant']}, File: {rec['file']}")
        print(f"  Hash: {rec['hash']}")
        print(f"  Signature: {rec['signature'][:80]}...\n  Package: {rec['package']}\n")


# ---------- Main Menu ----------

def main_menu():
    print("Finsecure PDF Transfer Demo (AES-GCM + RSA key-wrap + RSA signatures)")
    while True:
        print("\n1) Generate keypair (user prefix)")
        print("2) Customer: Encrypt PDF, wrap AES key, sign")
        print("3) Merchant: Verify signature, unwrap AES key, decrypt")
        print("4) Auditor: Show log")
        print("5) Exit")
        choice = input("Choice: ").strip()
        if choice == '1':
            prefix = input("Key name prefix (eg 'customer' or 'merchant'): ").strip()
            action_generate_keys(prefix)
        elif choice == '2':
            action_encrypt_and_sign()
        elif choice == '3':
            action_verify_and_decrypt()
        elif choice == '4':
            action_audit_log()
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice")


if __name__ == '__main__':
    main_menu()
---------------------------------------------------------------------------------------------------------------------
import time, base64, os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

# ---------- AES Encryption / Decryption ----------
def aes_encrypt_file(file_bytes: bytes, key: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(file_bytes)
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def aes_decrypt_file(enc: dict, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(enc["nonce"]))
    pt = cipher.decrypt_and_verify(
        base64.b64decode(enc["ciphertext"]),
        base64.b64decode(enc["tag"])
    )
    return pt

# ---------- RSA Sign / Verify ----------
def rsa_generate(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

def rsa_sign_bytes(data: bytes, privkey: RSA.RsaKey) -> str:
    h = SHA512.new(data)
    sig = pkcs1_15.new(privkey).sign(h)
    return base64.b64encode(sig).decode()

def rsa_verify_bytes(data: bytes, signature_b64: str, pubkey: RSA.RsaKey) -> bool:
    h = SHA512.new(data)
    try:
        pkcs1_15.new(pubkey).verify(h, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False

# ---------- Auditor Log ----------
audit_log = []

def record_transaction(customer: str, merchant: str, filename: str, hash_val: str, signature: str):
    audit_log.append({
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'merchant': merchant,
        'file': filename,
        'hash': hash_val,
        'signature': signature
    })

# ---------- Main Menu ----------
def main_menu():
    customer_priv, customer_pub = rsa_generate()
    merchant_priv, merchant_pub = rsa_generate()
    aes_key = get_random_bytes(16)  # AES-128

    customer_name = "Customer1"
    merchant_name = "Merchant1"

    encrypted_package = None
    signature = None
    file_bytes = None
    hash_msg = None
    file_name = None

    while True:
        print("\n==== Finsecure Corp (AES + RSA) ====")
        print("1. Customer: Encrypt + Hash + Sign")
        print("2. Merchant: Verify + Decrypt")
        print("3. Auditor: View Transaction Log")
        print("4. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            file_name = input("Enter file path to encrypt: ").strip()
            if not os.path.exists(file_name):
                print("File not found!")
                continue
            with open(file_name, "rb") as f:
                file_bytes = f.read()

            encrypted_package = aes_encrypt_file(file_bytes, aes_key)
            hash_msg = SHA512.new(file_bytes).hexdigest()
            signature = rsa_sign_bytes(file_bytes, customer_priv)
            record_transaction(customer_name, merchant_name, os.path.basename(file_name), hash_msg, signature)

            print("\n[Customer] File encrypted & signed.")
            print("Ciphertext:", encrypted_package["ciphertext"][:100]+"...")  # shortened display
            print("SHA512 Hash:", hash_msg)
            print("RSA Signature (base64):", signature[:100]+"...")  # shortened display

        elif choice == "2":
            if not encrypted_package:
                print("\n[Merchant] No file to verify/decrypt yet.")
                continue
            if rsa_verify_bytes(file_bytes, signature, customer_pub):
                print("\n[Merchant] Signature verified.")
                decrypted_bytes = aes_decrypt_file(encrypted_package, aes_key)
                out_file = "decrypted_" + os.path.basename(file_name)
                with open(out_file, "wb") as f:
                    f.write(decrypted_bytes)
                print("Decrypted file saved as:", out_file)
            else:
                print("\n[Merchant] Signature verification failed!")

        elif choice == "3":
            print("\n[Auditor] Transaction Records:")
            for rec in audit_log:
                print(f"Time: {rec['time']}, Customer: {rec['customer']}, Merchant: {rec['merchant']}, File: {rec['file']}")
                print(f"  Hash: {rec['hash']}")
                print(f"  Signature: {rec['signature'][:80]}...\n")

        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main_menu()
---------------------------------------------------------------------------------------------------------------------
import base64
from Crypto.Cipher import AES

def aes192_encrypt_file(file_bytes: bytes, key: bytes) -> dict:
    if len(key) != 24:
        raise ValueError("AES-192 key must be 24 bytes")
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(file_bytes)
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }
def aes192_decrypt_file(enc: dict, key: bytes) -> bytes:
    if len(key) != 24:
        raise ValueError("AES-192 key must be 24 bytes")
    cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(enc["nonce"]))
    pt = cipher.decrypt_and_verify(
        base64.b64decode(enc["ciphertext"]),
        base64.b64decode(enc["tag"])
    )
    return pt
def aes256_encrypt_file(file_bytes: bytes, key: bytes) -> dict:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(file_bytes)
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }
def aes256_decrypt_file(enc: dict, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(enc["nonce"]))
    pt = cipher.decrypt_and_verify(
        base64.b64decode(enc["ciphertext"]),
        base64.b64decode(enc["tag"])
    )
    return pt
from Crypto.Cipher import DES

def des_encrypt_file(file_bytes: bytes, key: bytes) -> dict:
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    # Pad to multiple of 8
    pad_len = 8 - (len(file_bytes) % 8)
    file_bytes += bytes([pad_len]) * pad_len
    cipher = DES.new(key, DES.MODE_ECB)
    ct = cipher.encrypt(file_bytes)
    return {
        "ciphertext": base64.b64encode(ct).decode()
    }
def des_decrypt_file(enc: dict, key: bytes) -> bytes:
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    cipher = DES.new(key, DES.MODE_ECB)
    ct_bytes = base64.b64decode(enc["ciphertext"])
    pt_padded = cipher.decrypt(ct_bytes)
    # Remove padding
    pad_len = pt_padded[-1]
    return pt_padded[:-pad_len]
---------------------------------------------------------------------------------------------------------------
import hashlib, math, time, base64
from random import randint
from Crypto.Cipher import DES

# ---------- SHA-512 Hash ----------
def sha512_hash(message: str) -> str:
    return hashlib.sha512(message.encode()).hexdigest()

# ---------- DES Encryption / Decryption ----------
def des_encrypt(msg: str, key: bytes) -> dict:
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    data = msg.encode()
    pad_len = 8 - (len(data) % 8)
    data += bytes([pad_len]) * pad_len
    cipher = DES.new(key, DES.MODE_ECB)
    ct = cipher.encrypt(data)
    return {"ciphertext": base64.b64encode(ct).decode()}

def des_decrypt(enc_dict: dict, key: bytes) -> str:
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    cipher = DES.new(key, DES.MODE_ECB)
    ct = base64.b64decode(enc_dict["ciphertext"])
    pt_padded = cipher.decrypt(ct)
    pad_len = pt_padded[-1]
    return pt_padded[:-pad_len].decode()

# ---------- ElGamal Digital Signature ----------
def elgamal_keygen(p: int, g: int):
    x = randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, y, x)

def elgamal_sign(message: str, p: int, g: int, x: int) -> tuple:
    h = int(sha512_hash(message), 16)
    while True:
        k = randint(1, p - 2)
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return (r, s)

def elgamal_verify(message: str, sig: tuple, p: int, g: int, y: int) -> bool:
    r, s = sig
    if not (0 < r < p):
        return False
    h = int(sha512_hash(message), 16)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

# ---------- Auditor Log ----------
audit_log = []

def record_transaction(customer: str, merchant: str, hash_val: str, signature: tuple):
    audit_log.append({
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'merchant': merchant,
        'hash': hash_val,
        'signature': signature
    })

# ---------- Main Menu ----------
def main_menu():
    des_key = b'12345678'  # 8-byte DES key

    # ElGamal keys for signatures
    p_elg = 30803
    g_elg = 2
    p, g, y, x = elgamal_keygen(p_elg, g_elg)

    customer_name = "Customer1"
    merchant_name = "Merchant1"

    enc_package = None
    signature = None
    original_msg = None
    hash_msg = None

    while True:
        print("\n==== Finsecure Corp (DES Version) ====")
        print("1. Customer: Encrypt + Hash + Sign")
        print("2. Merchant: Verify + Decrypt")
        print("3. Auditor: View Transaction Log")
        print("4. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            msg = input("Enter transaction message: ")
            original_msg = msg
            enc_package = des_encrypt(msg, des_key)
            hash_msg = sha512_hash(msg)
            signature = elgamal_sign(msg, p, g, x)
            record_transaction(customer_name, merchant_name, hash_msg, signature)
            print("\n[Customer] Message encrypted & signed.")
            print("Ciphertext:", enc_package["ciphertext"])
            print("SHA512 Hash:", hash_msg)
            print("Signature (r,s):", signature)

        elif choice == "2":
            if not enc_package:
                print("\n[Merchant] No message to verify/decrypt yet.")
                continue
            if elgamal_verify(original_msg, signature, p, g, y):
                print("\n[Merchant] Signature verified.")
                decrypted = des_decrypt(enc_package, des_key)
                print("Decrypted Message:", decrypted)
            else:
                print("\n[Merchant] Signature verification failed!")

        elif choice == "3":
            print("\n[Auditor] Transaction Records:")
            for rec in audit_log:
                print(f"Time: {rec['time']}, Customer: {rec['customer']}, "
                      f"Merchant: {rec['merchant']}\n  Hash: {rec['hash']}\n  Signature: {rec['signature']}\n")

        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main_menu()
------------------------------------------------------------------------------------------------------------------
import hashlib, time, base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import os

# ---------- AES-128 Encryption / Decryption ----------
def aes_encrypt_file(file_bytes: bytes, key: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(file_bytes)
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def aes_decrypt_file(enc: dict, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(enc["nonce"]))
    pt = cipher.decrypt_and_verify(
        base64.b64decode(enc["ciphertext"]),
        base64.b64decode(enc["tag"])
    )
    return pt

# ---------- RSA Key Generation ----------
def rsa_generate(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

# ---------- RSA Sign / Verify ----------
def rsa_sign_bytes(data: bytes, privkey: RSA.RsaKey) -> str:
    h = SHA512.new(data)
    sig = pkcs1_15.new(privkey).sign(h)
    return base64.b64encode(sig).decode()

def rsa_verify_bytes(data: bytes, signature_b64: str, pubkey: RSA.RsaKey) -> bool:
    h = SHA512.new(data)
    try:
        pkcs1_15.new(pubkey).verify(h, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False

# ---------- SHA-512 Hash ----------
def sha512_hash_bytes(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()

# ---------- Audit Log ----------
audit_log = []

def record_transaction(user_role: str, file_name: str, hash_val: str, signature: str):
    audit_log.append({
        "time": time.strftime('%Y-%m-%d %H:%M:%S'),
        "role": user_role,
        "file": file_name,
        "hash": hash_val,
        "signature": signature
    })

def view_audit_log():
    if not audit_log:
        print("No transactions recorded yet.")
        return
    for rec in audit_log:
        print(f"Time: {rec['time']}, Role: {rec['role']}, File: {rec['file']}")
        print(f"  SHA512 Hash: {rec['hash']}")
        print(f"  RSA Signature: {rec['signature'][:80]}...\n")

# ---------- Menu-Driven System ----------
def hospital_system():
    # AES-128 key (shared for demo; in real hospital use secure key management)
    aes_key = get_random_bytes(16)
    # RSA keypair for signing
    admin_priv, admin_pub = rsa_generate()
    doctor_priv, doctor_pub = rsa_generate()

    stored_files = {}  # filename -> {"encrypted": dict, "signature": str, "hash": str}

    while True:
        print("\n==== Hospital Secure System ====")
        print("1. Patient: Encrypt PDF")
        print("2. Doctor: Verify & Decrypt PDF")
        print("3. Admin: Full Access")
        print("4. Exit")
        choice = input("Enter choice: ").strip()

        if choice == "1":
            file_path = input("Enter path of PDF to encrypt: ").strip()
            if not os.path.isfile(file_path):
                print("File not found!")
                continue
            with open(file_path, "rb") as f:
                file_bytes = f.read()

            enc_package = aes_encrypt_file(file_bytes, aes_key)
            signature = rsa_sign_bytes(file_bytes, admin_priv)
            file_hash = sha512_hash_bytes(file_bytes)

            stored_files[file_path] = {
                "encrypted": enc_package,
                "signature": signature,
                "hash": file_hash
            }

            record_transaction("Patient", file_path, file_hash, signature)
            print(f"[Patient] File encrypted, signed, and hash recorded.")

        elif choice == "2":
            if not stored_files:
                print("No files available!")
                continue
            print("Available files:")
            for i, fname in enumerate(stored_files.keys(), 1):
                print(f"{i}. {fname}")
            sel = int(input("Select file number: ")) - 1
            if sel < 0 or sel >= len(stored_files):
                print("Invalid selection!")
                continue
            file_path = list(stored_files.keys())[sel]
            data = stored_files[file_path]

            sig_valid = rsa_verify_bytes(aes_decrypt_file(data["encrypted"], aes_key), data["signature"], admin_pub)
            if sig_valid:
                print("[Doctor] Signature verified.")
                decrypted_bytes = aes_decrypt_file(data["encrypted"], aes_key)
                out_file = "decrypted_" + os.path.basename(file_path)
                with open(out_file, "wb") as f:
                    f.write(decrypted_bytes)
                print(f"File decrypted successfully as '{out_file}'")
            else:
                print("[Doctor] Signature verification failed!")

        elif choice == "3":
            print("\n--- Admin Menu ---")
            print("1. View all files")
            print("2. View Audit Log")
            print("3. Decrypt any file")
            sub_choice = input("Enter choice: ").strip()
            if sub_choice == "1":
                if not stored_files:
                    print("No files available.")
                else:
                    for fname, val in stored_files.items():
                        print(f"File: {fname}, Hash: {val['hash'][:16]}..., Signature: {val['signature'][:16]}...")
            elif sub_choice == "2":
                view_audit_log()
            elif sub_choice == "3":
                if not stored_files:
                    print("No files available!")
                    continue
                print("Available files:")
                for i, fname in enumerate(stored_files.keys(), 1):
                    print(f"{i}. {fname}")
                sel = int(input("Select file number: ")) - 1
                if sel < 0 or sel >= len(stored_files):
                    print("Invalid selection!")
                    continue
                file_path = list(stored_files.keys())[sel]
                decrypted_bytes = aes_decrypt_file(stored_files[file_path]["encrypted"], aes_key)
                out_file = "admin_decrypted_" + os.path.basename(file_path)
                with open(out_file, "wb") as f:
                    f.write(decrypted_bytes)
                print(f"File decrypted successfully as '{out_file}'")
            else:
                print("Invalid choice!")

        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option!")

if __name__ == "__main__":
    hospital_system()
-----------------------------------------------------------------------------------------------------------------
import hashlib, time, base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

# ---------- AES-128 Encryption / Decryption ----------
def aes_encrypt(msg: str, key: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(msg.encode())
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def aes_decrypt(enc: dict, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(enc["nonce"]))
    pt = cipher.decrypt_and_verify(
        base64.b64decode(enc["ciphertext"]),
        base64.b64decode(enc["tag"])
    )
    return pt.decode()

# ---------- RSA Key Generation ----------
def rsa_generate(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

# ---------- RSA Sign / Verify ----------
def rsa_sign(msg: str, privkey: RSA.RsaKey) -> str:
    h = SHA512.new(msg.encode())
    sig = pkcs1_15.new(privkey).sign(h)
    return base64.b64encode(sig).decode()

def rsa_verify(msg: str, signature_b64: str, pubkey: RSA.RsaKey) -> bool:
    h = SHA512.new(msg.encode())
    try:
        pkcs1_15.new(pubkey).verify(h, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False

# ---------- SHA-512 Hash ----------
def sha512_hash(msg: str) -> str:
    return hashlib.sha512(msg.encode()).hexdigest()

# ---------- Audit Log ----------
audit_log = []

def record_transaction(user_role: str, message: str, hash_val: str, signature: str):
    audit_log.append({
        "time": time.strftime('%Y-%m-%d %H:%M:%S'),
        "role": user_role,
        "message": message,
        "hash": hash_val,
        "signature": signature
    })

def view_audit_log():
    if not audit_log:
        print("No transactions recorded yet.")
        return
    for rec in audit_log:
        print(f"Time: {rec['time']}, Role: {rec['role']}, Message: {rec['message']}")
        print(f"  SHA512 Hash: {rec['hash']}")
        print(f"  RSA Signature: {rec['signature'][:80]}...\n")

# ---------- Menu-Driven System ----------
def hospital_system():
    aes_key = get_random_bytes(16)  # AES-128 key
    # RSA keypair for signing
    admin_priv, admin_pub = rsa_generate()
    doctor_priv, doctor_pub = rsa_generate()

    stored_msgs = {}  # message -> {"encrypted": dict, "signature": str, "hash": str}

    while True:
        print("\n==== Hospital Secure System ====")
        print("1. Patient: Encrypt Message")
        print("2. Doctor: Verify & Decrypt Message")
        print("3. Admin: Full Access")
        print("4. Exit")
        choice = input("Enter choice: ").strip()

        if choice == "1":
            msg = input("Enter message to encrypt: ").strip()
            enc_package = aes_encrypt(msg, aes_key)
            signature = rsa_sign(msg, admin_priv)
            msg_hash = sha512_hash(msg)

            stored_msgs[msg] = {
                "encrypted": enc_package,
                "signature": signature,
                "hash": msg_hash
            }

            record_transaction("Patient", msg, msg_hash, signature)
            print(f"[Patient] Message encrypted, signed, and hash recorded.")

        elif choice == "2":
            if not stored_msgs:
                print("No messages available!")
                continue
            print("Available messages:")
            for i, m in enumerate(stored_msgs.keys(), 1):
                print(f"{i}. {m[:50]}...")
            sel = int(input("Select message number: ")) - 1
            if sel < 0 or sel >= len(stored_msgs):
                print("Invalid selection!")
                continue
            msg_key = list(stored_msgs.keys())[sel]
            data = stored_msgs[msg_key]

            if rsa_verify(msg_key, data["signature"], admin_pub):
                print("[Doctor] Signature verified.")
                decrypted_msg = aes_decrypt(data["encrypted"], aes_key)
                print(f"Decrypted Message: {decrypted_msg}")
            else:
                print("[Doctor] Signature verification failed!")

        elif choice == "3":
            print("\n--- Admin Menu ---")
            print("1. View all messages")
            print("2. View Audit Log")
            print("3. Decrypt any message")
            sub_choice = input("Enter choice: ").strip()
            if sub_choice == "1":
                if not stored_msgs:
                    print("No messages available.")
                else:
                    for msg, val in stored_msgs.items():
                        print(f"Message: {msg[:50]}..., Hash: {val['hash'][:16]}..., Signature: {val['signature'][:16]}...")
            elif sub_choice == "2":
                view_audit_log()
            elif sub_choice == "3":
                if not stored_msgs:
                    print("No messages available!")
                    continue
                print("Available messages:")
                for i, m in enumerate(stored_msgs.keys(), 1):
                    print(f"{i}. {m[:50]}...")
                sel = int(input("Select message number: ")) - 1
                if sel < 0 or sel >= len(stored_msgs):
                    print("Invalid selection!")
                    continue
                msg_key = list(stored_msgs.keys())[sel]
                decrypted_msg = aes_decrypt(stored_msgs[msg_key]["encrypted"], aes_key)
                print(f"Decrypted Message: {decrypted_msg}")
            else:
                print("Invalid choice!")

        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option!")

if __name__ == "__main__":
    hospital_system()
-----------------------------------------------------------------------------------------------------------------
# des_elgamal_example.py
"""
DES (CBC) encryption + SHA-512 + ElGamal signature
Note: Single DES is insecure for production. This is educational/demo code only.
Requires: pycryptodome
pip install pycryptodome
"""

import hashlib
import random, math, time
from random import randint
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import base64

# ---------- SHA-512 ----------
def sha512_hash(message: str) -> str:
    return hashlib.sha512(message.encode()).hexdigest()

# ---------- Padding for DES (PKCS5, block size 8) ----------
def pkcs5_pad(data: bytes) -> bytes:
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len]) * pad_len

def pkcs5_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

# ---------- DES encrypt/decrypt ----------
def des_keygen() -> bytes:
    # 8 bytes key for single DES
    return get_random_bytes(8)

def des_encrypt(plaintext: str, key: bytes) -> str:
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs5_pad(plaintext.encode()))
    return base64.b64encode(iv + ct).decode()

def des_decrypt(b64_cipher: str, key: bytes) -> str:
    raw = base64.b64decode(b64_cipher)
    iv, ct = raw[:8], raw[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = pkcs5_unpad(cipher.decrypt(ct))
    return pt.decode()

# ---------- ElGamal ----------
def elgamal_keygen(p: int, g: int):
    x = randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, y, x)

def elgamal_sign(message: str, p: int, g: int, x: int):
    h = int(sha512_hash(message), 16)
    while True:
        k = randint(1, p - 2)
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return (r, s)

def elgamal_verify(message: str, sig: tuple, p: int, g: int, y: int) -> bool:
    r, s = sig
    if not (0 < r < p):
        return False
    h = int(sha512_hash(message), 16)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

# ---------- Auditor Log ----------
audit_log = []

def record_transaction(customer: str, merchant: str, hash_val: str, signature: tuple):
    audit_log.append({
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'merchant': merchant,
        'hash': hash_val,
        'signature': signature
    })

# ---------- Main ----------
def main_menu():
    # DES symmetric key (customer & merchant share)
    des_key = des_keygen()

    # ElGamal params
    p_elg = 30803
    g_elg = 2
    p, g, y, x = elgamal_keygen(p_elg, g_elg)

    customer_name = "Customer_DES"
    merchant_name = "Merchant_DES"

    encrypted_msg = None
    signature = None
    original_msg = None
    hash_msg = None

    while True:
        print("\n==== DES + ElGamal Menu ====")
        print("1. Customer: Encrypt + Hash + Sign")
        print("2. Merchant: Verify + Decrypt")
        print("3. Auditor: View Transaction Log")
        print("4. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            msg = input("Enter transaction message: ")
            original_msg = msg
            encrypted_msg = des_encrypt(msg, des_key)
            hash_msg = sha512_hash(msg)
            signature = elgamal_sign(msg, p, g, x)
            record_transaction(customer_name, merchant_name, hash_msg, signature)
            print("\n[Customer] Message encrypted & signed.")
            print("Ciphertext (base64 IV+cipher):", encrypted_msg)
            print("SHA512 Hash:", hash_msg)
            print("Signature (r,s):", signature)

        elif choice == "2":
            if not encrypted_msg:
                print("\n[Merchant] No message to verify/decrypt yet.")
                continue
            if elgamal_verify(original_msg, signature, p, g, y):
                print("\n[Merchant] Signature verified.")
                decrypted = des_decrypt(encrypted_msg, des_key)
                print("Decrypted Message:", decrypted)
            else:
                print("\n[Merchant] Signature verification failed!")

        elif choice == "3":
            print("\n[Auditor] Transaction Records:")
            for rec in audit_log:
                print(f"Time: {rec['time']}, Customer: {rec['customer']}, "
                      f"Merchant: {rec['merchant']}\n  Hash: {rec['hash']}\n  Signature: {rec['signature']}\n")

        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main_menu()

----------------------------------------------------------------------------------------------------------------------
"""
Diffie-Hellman key exchange between two peers with RSA-PSS signatures and SHA-512 hashing.
Measures time for key generation and exchange steps.

Requires: pip install cryptography
"""

import time
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, NoEncryption, PrivateFormat
)


# ---------------------------
# Helper functions
# ---------------------------
def current_ms() -> float:
    """Return current time in milliseconds (float)."""
    return time.perf_counter() * 1000.0


def sha512_digest(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


# ---------------------------
# Peer class
# ---------------------------
@dataclass
class Peer:
    name: str
    rsa_private: rsa.RSAPrivateKey
    rsa_public: rsa.RSAPublicKey
    dh_private: dh.DHPrivateKey = None
    dh_public: dh.DHPublicKey = None

    @staticmethod
    def generate_rsa(bits: int = 2048):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        pub = priv.public_key()
        return priv, pub

    def generate_dh_keys(self, dh_parameters: dh.DHParameters):
        """Generate a DH private/public key pair from shared DH parameters."""
        self.dh_private = dh_parameters.generate_private_key()
        self.dh_public = self.dh_private.public_key()

    def dh_public_bytes(self) -> bytes:
        """Return serialized DH public key (PEM)."""
        return self.dh_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def rsa_public_bytes(self) -> bytes:
        return self.rsa_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def sign(self, data: bytes) -> bytes:
        """Sign given bytes with RSA-PSS and SHA-512."""
        signature = self.rsa_private.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        return signature

    @staticmethod
    def verify_signature(pub_bytes: bytes, signature: bytes, signed_data: bytes) -> bool:
        """Verify signature using serialized RSA public key bytes."""
        pub = serialization.load_pem_public_key(pub_bytes)
        try:
            pub.verify(
                signature,
                signed_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )
            return True
        except Exception:
            return False

    def compute_shared_secret(self, peer_dh_pub_bytes: bytes) -> bytes:
        """Compute raw DH shared secret from peer's DH public PEM bytes."""
        peer_pub = serialization.load_pem_public_key(peer_dh_pub_bytes)
        # perform key exchange
        shared = self.dh_private.exchange(peer_pub)
        return shared

    @staticmethod
    def derive_key_from_shared(shared_secret: bytes, info: bytes = b'') -> bytes:
        """Derive symmetric key bytes from raw shared secret using SHA-512.
           (For production use HKDF or another KDF.)"""
        # Concatenate info (optional) before hashing
        return sha512_digest(shared_secret + info)


# ---------------------------
# Demo flow: two peers (A <-> B)
# ---------------------------
def demo_two_peers():
    print("=== Diffie-Hellman + RSA-PSS (SHA-512) demo ===\n")

    # 1) Generate shared DH parameters (done once, distributed to peers)
    t0 = current_ms()
    dh_params = dh.generate_parameters(generator=2, key_size=2048)  # 2048-bit group
    t1 = current_ms()
    dh_param_gen_time_ms = t1 - t0
    print(f"[Timing] DH parameter generation: {dh_param_gen_time_ms:.2f} ms")

    # 2) Generate RSA keys and DH keys for each peer and measure times
    peers = {}
    for name in ("PeerA", "PeerB"):
        t_start = current_ms()
        rsa_priv, rsa_pub = Peer.generate_rsa(bits=2048)
        t_after_rsa = current_ms()
        rsa_gen_time_ms = t_after_rsa - t_start

        # Create peer object
        p = Peer(name=name, rsa_private=rsa_priv, rsa_public=rsa_pub)

        # Generate DH key pair
        t_dh_start = current_ms()
        p.generate_dh_keys(dh_params)
        t_dh_end = current_ms()
        dh_keygen_time_ms = t_dh_end - t_dh_start

        peers[name] = {
            "obj": p,
            "rsa_gen_ms": rsa_gen_time_ms,
            "dh_keygen_ms": dh_keygen_time_ms
        }

        print(f"[{name}] RSA key generation: {rsa_gen_time_ms:.2f} ms; DH keypair generation: {dh_keygen_time_ms:.2f} ms")

    # 3) Exchange sequence (over insecure channel)
    # Each peer sends: its RSA public key bytes, its DH public bytes, and a signature over the DH public bytes.
    A: Peer = peers["PeerA"]["obj"]
    B: Peer = peers["PeerB"]["obj"]

    # Create outgoing messages
    msgA = {
        "rsa_pub": A.rsa_public_bytes(),
        "dh_pub": A.dh_public_bytes()
    }
    signatureA = A.sign(msgA["dh_pub"])

    msgB = {
        "rsa_pub": B.rsa_public_bytes(),
        "dh_pub": B.dh_public_bytes()
    }
    signatureB = B.sign(msgB["dh_pub"])

    # Measure exchange/verification/compute times (A verifies B and computes shared; B verifies A and computes shared)
    # A side:
    t_exchange_start_A = current_ms()
    # A receives B's rsa_pub, dh_pub, signatureB
    okB = Peer.verify_signature(msgB["rsa_pub"], signatureB, msgB["dh_pub"])
    t_verify_B = current_ms()
    verify_B_ms = t_verify_B - t_exchange_start_A

    if not okB:
        print("[A] Signature from B failed verification! Abort.")
        return

    # A computes shared secret and derives symmetric key
    shared_A = A.compute_shared_secret(msgB["dh_pub"])
    derived_key_A = Peer.derive_key_from_shared(shared_A, info=b"A->B")
    t_after_A = current_ms()
    compute_A_ms = t_after_A - t_verify_B

    # B side:
    t_exchange_start_B = current_ms()
    okA = Peer.verify_signature(msgA["rsa_pub"], signatureA, msgA["dh_pub"])
    t_verify_A = current_ms()
    verify_A_ms = t_verify_A - t_exchange_start_B

    if not okA:
        print("[B] Signature from A failed verification! Abort.")
        return

    shared_B = B.compute_shared_secret(msgA["dh_pub"])
    derived_key_B = Peer.derive_key_from_shared(shared_B, info=b"A->B")  # same info
    t_after_B = current_ms()
    compute_B_ms = t_after_B - t_verify_A

    # Results and verification
    print("\n--- Results ---")
    print(f"[Timing] A verified B signature in {verify_B_ms:.2f} ms and computed shared key in {compute_A_ms:.2f} ms")
    print(f"[Timing] B verified A signature in {verify_A_ms:.2f} ms and computed shared key in {compute_B_ms:.2f} ms")

    print("\nDerived symmetric key (SHA-512 digest) lengths:")
    print(" - A key len:", len(derived_key_A))
    print(" - B key len:", len(derived_key_B))

    same = derived_key_A == derived_key_B
    print("\nShared secrets match on both peers?:", same)

    if same:
        print("Shared key (first 64 hex chars):", derived_key_A.hex()[:64])
    else:
        print("ERROR: shared keys mismatch!")

    # Show SHA-512 of the plaintext/shared secret too (optional)
    print("\nSHA-512 hash of raw shared secret (A):", hashlib.sha512(shared_A).hexdigest()[:64])
    print("SHA-512 hash of raw shared secret (B):", hashlib.sha512(shared_B).hexdigest()[:64])

    print("\nDemo complete. (Use HKDF + AEAD (AES-GCM/ChaCha20-Poly1305) for production symmetric key derivation & encryption.)")


if __name__ == "__main__":
    demo_two_peers()
---------------------------------------------------------------------------------------------------------------------
