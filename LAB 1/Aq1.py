import string

cipher = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"
alpha = string.ascii_uppercase
m = 26

possible_keys = [k % m for k in range(8, 19)]

def add_dec(ciphertext, key):
    plaintext = ""
    for ch in ciphertext:
        if ch in alpha:
            idx = (alpha.index(ch) - key) % m
            plaintext += alpha[idx]
        else:
            plaintext += ch
    return plaintext

for key in possible_keys:
    plaintext = add_dec(cipher, key)
    print(f"Key = {key}: {plaintext}")