import string

plain = "We live in an insecure world".replace(" ", "").lower()
alpha = string.ascii_lowercase
m = 26

K = [[3, 3],
     [2, 7]]

def matrix_inverse_2x2(mat):
    det = (mat[0][0]*mat[1][1] - mat[0][1]*mat[1][0]) % m
    det_inv = pow(det, -1, m)
    adj = [[ mat[1][1] * det_inv % m, (-mat[0][1]) * det_inv % m],
           [(-mat[1][0]) * det_inv % m,  mat[0][0] * det_inv % m]]
    return adj

def hill_enc(text, key):
    if len(text) % 2 != 0:
        text += 'x'
    cipher = ""
    for i in range(0, len(text), 2):
        pair = text[i:i+2]
        v = [alpha.index(c) for c in pair]
        c0 = (key[0][0]*v[0] + key[0][1]*v[1]) % m
        c1 = (key[1][0]*v[0] + key[1][1]*v[1]) % m
        cipher += alpha[c0] + alpha[c1]
    return cipher

ciphertext = hill_enc(plain, K)

print("Hill cipher key matrix:", K)
print("Plaintext (no spaces):", plain)
print("Ciphertext:", ciphertext)