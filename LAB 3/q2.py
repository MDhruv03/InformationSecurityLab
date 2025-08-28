from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os

# Generate recipient ECC key pair
priv = ECC.generate(curve="P-256")
pub = priv.public_key()

msg = b"Secure Transactions"

# --- Encrypt with public key ---
ephemeral = ECC.generate(curve="P-256")
# shared secret via ECDH
shared = (ephemeral.d * pub.pointQ).x.to_bytes(32, "big")
key = SHA256.new(shared).digest()[:16]

nonce = os.urandom(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ct, tag = cipher.encrypt_and_digest(msg)

ciphertext = (ephemeral.export_key(format="DER"), nonce, ct, tag)

# --- Decrypt with private key ---
ephemeral_pub = ECC.import_key(ciphertext[0])
shared2 = (priv.d * ephemeral_pub.pointQ).x.to_bytes(32, "big")
key2 = SHA256.new(shared2).digest()[:16]

cipher2 = AES.new(key2, AES.MODE_GCM, nonce=ciphertext[1])
pt = cipher2.decrypt_and_verify(ciphertext[2], ciphertext[3])

print("Ciphertext (hex):", ciphertext[2].hex())
print("Decrypted:", pt.decode())
