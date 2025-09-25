# 2. Try using the Diffie-Hellman asymmetric encryption standard and verify the above
# steps.

from Crypto.Util.number import getPrime
import random
import time

# Generates the public parameters (a large prime p and a generator g).
def generate_public_params(bits=256):
    p = getPrime(bits)
    g = random.randrange(2, p-1)
    return g, p

# Represents Alice in the key exchange.
class Alice:
    def __init__(self, g, p):
        # Store the public parameters.
        self.g, self.p = g, p
        # Alice generates her own private key 'a', a random secret number.
        self.private_key = random.randrange(2, p-2)
        # She computes her public key 'A' and shares it with Bob.
        self.public_key = pow(g, self.private_key, p)
        self.shared_secret = None
        print("Alice has generated her keys.")

    # Computes the shared secret using her private key and Bob's public key.
    def compute_shared_secret(self, bob_public_key):
        # Alice calculates: s = (Bob's Public Key) ^ (Her Private Key) mod p
        self.shared_secret = pow(bob_public_key, self.private_key, self.p)
        return self.shared_secret

# Represents Bob in the key exchange.
class Bob:
    def __init__(self, g, p):
        self.g, self.p = g, p
        # Bob generates his own private key 'b'.
        self.private_key = random.randrange(2, p-2)
        # He computes his public key 'B' and shares it with Alice.
        self.public_key = pow(g, self.private_key, p)
        self.shared_secret = None
        print("Bob has generated his keys.")

    # Computes the shared secret using his private key and Alice's public key.
    def compute_shared_secret(self, alice_public_key):
        # Bob calculates: s = (Alice's Public Key) ^ (His Private Key) mod p
        self.shared_secret = pow(alice_public_key, self.private_key, self.p)
        return self.shared_secret

if __name__ == "__main__":
    # 1. Agree on public parameters (can be done over an insecure channel).
    print("--- 1. Generating Public Parameters ---")
    g, p = generate_public_params()
    print(f"Public Prime (p) starts with: {str(p)[:15]}...")
    print(f"Public Generator (g): {g}\n")

    # 2. Alice and Bob generate their individual private and public keys.
    print("--- 2. Key Generation ---")
    alice = Alice(g, p)
    bob = Bob(g, p)
    print(f"Alice's Public Key (A): {alice.public_key}")
    print(f"Bob's Public Key (B): {bob.public_key}\n")

    # 3. They exchange public keys and compute the shared secret.
    print("--- 3. Computing Shared Secret ---")
    # Alice uses Bob's public key.
    secret_for_alice = alice.compute_shared_secret(bob.public_key)
    # Bob uses Alice's public key.
    secret_for_bob = bob.compute_shared_secret(alice.public_key)

    # 4. Verification: Both should arrive at the exact same number.
    print(f"Alice's computed secret: {secret_for_alice}")
    print(f"Bob's computed secret  : {secret_for_bob}")
    
    print("\n--- 4. Verification ---")
    if secret_for_alice == secret_for_bob:
        print("Success! Both Alice and Bob computed the same shared secret.")
    else:
        print("Failure! The secrets do not match.")
        
    assert secret_for_alice == secret_for_bob