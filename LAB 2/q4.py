from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

pt = "Classified Text"
k = "1234567890ABCDEF9876543210FEDCBA5555AAAA3333CCCC"
# k = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
key = bytes.fromhex(k)
key = DES3.adjust_key_parity(key)
block_size = 8

cipher = DES3.new(key, DES3.MODE_ECB)

padded_message = pad(pt.encode(), block_size)

ct = cipher.encrypt(padded_message)
print(f"Ciphertext (hex): {ct.hex()}")

mes = unpad(cipher.decrypt(ct), block_size).decode()
print(f"Decrypted Message: {mes}")

print(f"\nVerification: {pt == mes}")