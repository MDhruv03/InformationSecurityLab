from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random

# Key generation
def elgamal_keygen(bits=2048):
    p = getPrime(bits)
    g = random.randrange(2, p - 1)
    x = random.randrange(1, p - 2)  # private key
    h = pow(g, x, p)               # public key
    return (p, g, h), x

# Encrypt
def elgamal_encrypt(pk, plaintext):
    p, g, h = pk
    m = bytes_to_long(plaintext)
    k = random.randrange(1, p - 2)
    c1 = pow(g, k, p)
    s = pow(h, k, p)
    c2 = (m * s) % p
    return (c1, c2)

# Decrypt
def elgamal_decrypt(sk, pk, ciphertext):
    p, g, h = pk
    x = sk
    c1, c2 = ciphertext
    s = pow(c1, x, p)
    m = (c2 * inverse(s, p)) % p
    return long_to_bytes(m)

# Example usage
pk, sk = elgamal_keygen()
msg = b"Confidential Data"
cipher = elgamal_encrypt(pk, msg)
decrypted = elgamal_decrypt(sk, pk, cipher)

print("Original:", msg)
print("Cipher:", cipher)
print("Decrypted:", decrypted)
