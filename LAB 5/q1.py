# 1. Implement the hash function in Python. Your function should start with an initial hash
# value of 5381 and for each character in the input string, multiply the current hash value
# by 33, add the ASCII value of the character, and use bitwise operations to ensure
# thorough mixing of the bits. Finally, ensure the hash value is kept within a 32-bit range
# by applying an appropriate mask.



# ===================================================
# Custom Hash Function Implementation (32-bit)
# ===================================================

def custom_hash(input_string):
    """
    Implements a hash function with the following properties:
    - Initial hash value: 5381
    - Multiplies current hash by 33
    - Adds ASCII value of each character
    - Applies bitwise mixing for better diffusion
    - Ensures final hash is within 32-bit range
    """
    # -------------------------------
    # Step 1: Initialize the hash value
    # -------------------------------
    hash_value = 5381  # Starting value (commonly used in DJB2 hash)
    
    # -------------------------------
    # Step 2: Iterate over each character
    # -------------------------------
    for char in input_string:
        ascii_val = ord(char)            # Convert character to ASCII integer
        hash_value = (hash_value * 33)   # Multiply current hash by 33
        hash_value = hash_value + ascii_val  # Add ASCII value of the character
        
        # -------------------------------
        # Step 3: Optional bitwise mixing
        # -------------------------------
        # XOR the hash with its right-shifted version to mix bits further
        hash_value = hash_value ^ (hash_value >> 16)
        
        # Keep hash within 32-bit unsigned integer range
        hash_value = hash_value & 0xFFFFFFFF

    # -------------------------------
    # Step 4: Return final 32-bit hash value
    # -------------------------------
    return hash_value

# ===============================
# Example Usage
# ===============================
if __name__ == "__main__":
    test_string = "Hello, World!"
    hash_result = custom_hash(test_string)
    print(f"Input String: '{test_string}'")
    print(f"Hash Value (32-bit): {hash_result}")