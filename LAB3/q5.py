from Crypto.Util.number import getPrime
import random, time

def diffie_hellman_key_exchange(bits=2048):
    p = getPrime(bits)
    g = 2  # generator

    # Peer A
    a = random.randrange(2, p - 2)
    A = pow(g, a, p)

    # Peer B
    b = random.randrange(2, p - 2)
    B = pow(g, b, p)

    # Shared secret
    start_time = time.time()
    shared_A = pow(B, a, p)
    shared_B = pow(A, b, p)
    elapsed = time.time() - start_time

    assert shared_A == shared_B
    return p, g, a, b, shared_A, elapsed

p, g, a, b, shared_key, duration = diffie_hellman_key_exchange()
print(f"Shared key: {shared_key}")
print(f"Key exchange duration: {duration:.6f} seconds")
