from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes

# RSA Key Generation
def generate_rsa_keys(key_size=1024):
    # Step 1: Generate two large primes
    p = getPrime(key_size)
    q = getPrime(key_size)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Step 2: Choose public exponent e
    e = 65537  # Commonly used prime exponent
    if GCD(e, phi) != 1:
        e = 3
        while GCD(e, phi) != 1:
            e += 2

    # Step 3: Compute private exponent d
    d = inverse(e, phi)

    return (e, d, n)

# RSA Encryption
def rsa_encrypt(message: bytes, e: int, n: int) -> int:
    m = bytes_to_long(message)
    if m >= n:
        raise ValueError("Message too large for the key size.")
    c = pow(m, e, n)
    return c

# RSA Decryption
def rsa_decrypt(ciphertext: int, d: int, n: int) -> bytes:
    m = pow(ciphertext, d, n)
    return long_to_bytes(m)

# Main test
if __name__ == "__main__":
    message = b"Yur"

    # Generate keys
    e, d, n = generate_rsa_keys(1024)
    print(f"Public Key (e, n): ({e}, {n})")
    print(f"Private Key (d, n): ({d}, {n})")

    # Encrypt
    ciphertext = rsa_encrypt(message, e, n)
    print("Ciphertext:", ciphertext)

    # Decrypt
    decrypted_message = rsa_decrypt(ciphertext, d, n)
    print("Decrypted:", decrypted_message.decode())
