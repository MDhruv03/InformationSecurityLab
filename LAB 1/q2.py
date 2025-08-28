import string

plain = "the house is being sold tonight".replace(" ", "").lower()
alpha = string.ascii_lowercase
m = 26

def vigenere_enc(text, key):
    key_stream = (key * ((len(text) // len(key)) + 1))[:len(text)]
    return "".join(
        alpha[(alpha.index(c) + alpha.index(k)) % m]
        for c, k in zip(text, key_stream)
    )

def vigenere_dec(cipher, key):
    key_stream = (key * ((len(cipher) // len(key)) + 1))[:len(cipher)]
    return "".join(
        alpha[(alpha.index(c) - alpha.index(k)) % m]
        for c, k in zip(cipher, key_stream)
    )

def autokey_enc(text, key_shift):
    cipher = []
    prev = key_shift
    for c in text:
        shift = prev
        ci = alpha[(alpha.index(c) + shift) % m]
        cipher.append(ci)
        prev = alpha.index(c)
    return "".join(cipher)

def autokey_dec(cipher, key_shift):
    plain = []
    prev = key_shift
    for c in cipher:
        pi = alpha[(alpha.index(c) - prev) % m]
        plain.append(pi)
        prev = alpha.index(pi)
    return "".join(plain)

vig_key = "dollars"
auto_key = 7

c_vig = vigenere_enc(plain, vig_key)
d_vig = vigenere_dec(c_vig, vig_key)

c_auto = autokey_enc(plain, auto_key)
d_auto = autokey_dec(c_auto, auto_key)

print("Vigenère cipher:", c_vig)
print("Decrypted:", d_vig)
print("Autokey cipher:", c_auto)
print("Decrypted:", d_auto)