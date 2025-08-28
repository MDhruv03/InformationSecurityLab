from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

pt = "Top Secret Data"
k = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
key = bytes.fromhex(k)

print(f"Plaintext: {pt}")
print(f"Key (hex): {k}")
print(f"AES Mode: AES-192")

cipher = AES.new(key, AES.MODE_ECB)

p = pad(pt.encode(), AES.block_size)
print(f"Padded Message (bytes): {p}")
print(f"Padded length: {len(p)} bytes")

print(f"\nENCRYPTION PROCESS")
print(f"1. Key Expansion: 192-bit key expanded to 13 round keys")
print(f"2. Initial Round: AddRoundKey with round key 0")
print(f"3. Main Rounds: 11 rounds (SubBytes, ShiftRows, MixColumns, AddRoundKey)")
print(f"4. Final Round: SubBytes, ShiftRows, AddRoundKey (no MixColumns)")

ct = cipher.encrypt(p)
print(f"\nCiphertext (hex): {ct.hex()}")
print(f"Ciphertext length: {len(ct)} bytes")

print(f"\nDECRYPTION VERIFICATION")
mes = unpad(cipher.decrypt(ct), AES.block_size).decode()
print(f"Decrypted Message: {mes}")

print(f"\nVerification: {pt == mes}")