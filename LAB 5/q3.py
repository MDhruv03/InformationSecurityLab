# 3. Design a Python-based experiment to analyze the performance of MD5, SHA-1, and
# SHA-256 hashing techniques in terms of computation time and collision resistance.
# Generate a dataset of random strings ranging from 50 to 100 strings, compute the hash
# values using each hashing technique, and measure the time taken for hash computation.
# Implement collision detection algorithms to identify any collisions within the hashed



# ================================================================
# Experiment: Performance and Collision Analysis of Hash Functions
# ================================================================

import hashlib
import random
import string
import time

# -------------------------------
# Helper Function: Generate Random Strings
# -------------------------------
def generate_random_strings(num_strings=50, min_len=5, max_len=20):
    """
    Generate a list of random strings.
    Each string length is random between min_len and max_len.
    """
    random_strings = []
    for _ in range(num_strings):
        length = random.randint(min_len, max_len)
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        random_strings.append(s)
    return random_strings

# -------------------------------
# Helper Function: Compute Hash
# -------------------------------
def compute_hashes(data_list, algorithm='md5'):
    """
    Compute hash values for a list of strings using specified algorithm.
    Supported algorithms: 'md5', 'sha1', 'sha256'.
    Returns a dictionary mapping original strings to their hashes.
    """
    hash_dict = {}
    start_time = time.perf_counter()  # Start timing

    for item in data_list:
        # Convert string to bytes
        data_bytes = item.encode()

        # Select hash algorithm
        if algorithm.lower() == 'md5':
            h = hashlib.md5()
        elif algorithm.lower() == 'sha1':
            h = hashlib.sha1()
        elif algorithm.lower() == 'sha256':
            h = hashlib.sha256()
        else:
            raise ValueError("Unsupported algorithm. Choose md5, sha1, or sha256.")

        # Compute hash
        h.update(data_bytes)
        digest = h.hexdigest()
        hash_dict[item] = digest

    end_time = time.perf_counter()  # End timing
    time_taken = end_time - start_time
    return hash_dict, time_taken

# -------------------------------
# Helper Function: Detect Collisions
# -------------------------------
def detect_collisions(hash_dict):
    """
    Detect collisions in the given hash dictionary.
    Returns a list of tuples with colliding original strings.
    """
    seen_hashes = {}
    collisions = []

    for original, digest in hash_dict.items():
        if digest in seen_hashes:
            collisions.append((seen_hashes[digest], original))
        else:
            seen_hashes[digest] = original

    return collisions

# -------------------------------
# Main Experiment
# -------------------------------
if __name__ == "__main__":
    # Step 1: Generate a dataset of random strings
    num_strings = random.randint(50, 100)  # Random dataset size
    dataset = generate_random_strings(num_strings, 5, 20)
    print(f"[INFO] Generated {len(dataset)} random strings for hashing experiment.")

    # Step 2: Analyze each hash algorithm
    for algo in ['md5', 'sha1', 'sha256']:
        print(f"\n[INFO] Computing hashes using {algo.upper()}...")
        hashes, time_taken = compute_hashes(dataset, algorithm=algo)
        collisions = detect_collisions(hashes)

        # Step 3: Report results
        print(f"Algorithm: {algo.upper()}")
        print(f"Time taken: {time_taken:.6f} seconds")
        print(f"Number of collisions: {len(collisions)}")
        if collisions:
            print(f"Collisions detected: {collisions}")
        else:
            print("No collisions detected.")