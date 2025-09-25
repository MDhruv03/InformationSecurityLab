# 1. Try using the Elgammal, Schnor asymmetric encryption standard and verify the above
# steps. 

from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes
import hashlib
import random
import time

# --- HASHING HELPER ---
# A standard function to hash a message using SHA-256.
def hash_message(msg: bytes):
    """Hashes a message using SHA-256 and returns the integer representation."""
    return bytes_to_long(hashlib.sha256(msg).digest())

# --- ELGAMAL DIGITAL SIGNATURE ---
class ElGamalSignature:
    # Generates the public and private keys.
    def generate_keys(self, bits=512):
        """
        Generates ElGamal keys.
        Public key: (p, g, h)
        Private key: x
        """
        p = getPrime(bits)
        # The generator 'g' is a primitive root modulo p, 2 is a common choice.
        g = 2
        # The private key 'x' is a random secret number.
        x = random.randint(2, p - 2)
        # The public key 'h' is computed from the private key.
        h = pow(g, x, p)
        
        self.public_key = (p, g, h)
        self.private_key = x
        print("ElGamal keys generated.")

    # Creates a digital signature for a message using the private key.
    def sign(self, msg: bytes):
        """Signs a message and returns the signature (r, s)."""
        p, g, h = self.public_key
        x = self.private_key
        
        # 1. Hash the message to get a number 'm'.
        m = hash_message(msg)
        
        # 2. Choose a secret random number 'k' for this signature only.
        # k must be coprime to p-1.
        k = random.randint(2, p - 2)
        while GCD(k, p - 1) != 1:
            k = random.randint(2, p - 2)
        
        # 3. Compute the two parts of the signature, r and s.
        r = pow(g, k, p)
        k_inv = inverse(k, p - 1)
        s = (k_inv * (m - x * r)) % (p - 1)
        
        # The signature is the pair (r, s).
        return (r, s)

    # Verifies a signature using the public key.
    def verify(self, msg: bytes, signature: tuple):
        """Verifies an ElGamal signature."""
        p, g, h = self.public_key
        r, s = signature
        
        # 1. Hash the message to get the same number 'm'.
        m = hash_message(msg)
        
        # 2. Perform the verification check.
        # Check if (h^r * r^s) mod p is equal to g^m mod p.
        left_side = (pow(h, r, p) * pow(r, s, p)) % p
        right_side = pow(g, m, p)
        
        return left_side == right_side

# --- SCHNORR DIGITAL SIGNATURE ---
class SchnorrSignature:
    # Generates keys. q is a prime factor of p-1.
    def generate_keys(self, p_bits=512):
        """
        Generates Schnorr keys. Fixes the inefficient prime generation loop.
        Public key: (p, q, g, h)
        Private key: x
        """
        print("\nGenerating Schnorr keys...")
        start_time = time.time()
        
        # Step 1: Find a prime 'q' first. This is a common practice.
        q_bits = 160
        q = getPrime(q_bits)

        # Step 2: Find a prime 'p' such that p-1 is divisible by q.
        # This is the corrected and more efficient approach.
        p_candidate = 2 * q + 1
        while not (p_candidate % q == 0 and getPrime(p_bits) and p_candidate.bit_length() == p_bits):
            # Generate a new prime 'p' candidate until a valid one is found.
            p_candidate = getPrime(p_bits)
            if (p_candidate - 1) % q == 0:
                p = p_candidate
                break
        else:
            print("Failed to find a suitable prime p. Please try again.")
            return

        # Step 3: Find a generator 'g' for the subgroup of order 'q'.
        h_val = random.randint(2, p - 2)
        g = pow(h_val, (p - 1) // q, p)
        while g == 1:
            h_val = random.randint(2, p - 2)
            g = pow(h_val, (p - 1) // q, p)

        # Step 4: Choose a private key 'x' and compute the public key 'h'.
        x = random.randint(2, q - 1)
        h = pow(g, x, p)

        self.public_key = (p, q, g, h)
        self.private_key = x
        end_time = time.time()
        print(f"Schnorr keys generated in {end_time - start_time:.4f} seconds.")

    # Creates a signature for a message.
    def sign(self, msg: bytes):
        """Signs a message and returns the signature (e, s)."""
        p, q, g, h = self.public_key
        x = self.private_key
        
        # 1. Choose a secret random number 'k'.
        k = random.randint(2, q - 1)
        r = pow(g, k, p)
        
        # 2. Hash the message concatenated with r.
        e = hash_message(msg + long_to_bytes(r))
        
        # 3. Compute the second part of the signature, s.
        s = (k - x * e) % q
        
        # The signature is (e, s).
        return (e, s)

    # Verifies a signature using the public key.
    def verify(self, msg: bytes, signature: tuple):
        """Verifies a Schnorr signature."""
        p, q, g, h = self.public_key
        e, s = signature
        
        # 1. Compute a value 'rv' from the signature and public key.
        # This is the verification equation: rv = g^s * h^e mod p
        rv = (pow(g, s, p) * pow(h, e, p)) % p
        
        # 2. Hash the message concatenated with the computed rv.
        ev = hash_message(msg + long_to_bytes(rv))
        
        # 3. Check if the computed hash matches the 'e' from the signature.
        return ev == e

if __name__ == "__main__":
    message = b"This is a signed document."
    
    # --- ElGamal Demo ---
    print("--- ElGamal Signature Demo ---")
    elgamal = ElGamalSignature()
    elgamal.generate_keys()
    signature_elg = elgamal.sign(message)
    is_valid_elg = elgamal.verify(message, signature_elg)
    print(f"Message: '{message.decode()}'")
    print(f"ElGamal Signature (r, s): {signature_elg}")
    print(f"ElGamal Verification successful? -> {is_valid_elg}")
    assert is_valid_elg
    
    # --- Schnorr Demo ---
    print("\n--- Schnorr Signature Demo ---")
    schnorr = SchnorrSignature()
    schnorr.generate_keys()
    signature_sch = schnorr.sign(message)
    is_valid_sch = schnorr.verify(message, signature_sch)
    print(f"Message: '{message.decode()}'")
    print(f"Schnorr Signature (e, s): {signature_sch}")
    print(f"Schnorr Verification successful? -> {is_valid_sch}")
    assert is_valid_sch