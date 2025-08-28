from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

pt = "Asymmetric Encryption"

key = RSA.generate(2048)
n = key.n
e = key.e
d = key.d

print(f"Plaintext: {pt}")
print(f"RSA key size: 2048 bits")
print(f"Public key (n): {hex(n)}")
print(f"Public exponent (e): {e}")
print(f"Private exponent (d): {hex(d)}")

public_key = RSA.construct((n, e))
private_key = RSA.construct((n, e, d))

cipher_encrypt = PKCS1_OAEP.new(public_key)
cipher_decrypt = PKCS1_OAEP.new(private_key)

ct = cipher_encrypt.encrypt(pt.encode())
print(f"Ciphertext (hex): {ct.hex()}")
print(f"Ciphertext length: {len(ct)} bytes")

mes = cipher_decrypt.decrypt(ct).decode()
print(f"Decrypted message: {mes}")

print(f"Original == Decrypted: {pt == mes}")