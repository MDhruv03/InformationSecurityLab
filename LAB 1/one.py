def clean_msg(msg):
    return msg.replace(" ", "").upper()

def mod_inverse(a, m=26):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def encrypt(msg, key, cipher_type):
    a, b = key if isinstance(key, tuple) else (key, 0)
    result = ""
    for ch in msg:
        if ch.isalpha():
            val = ord(ch) - 65
            if cipher_type == "additive":
                val = (val + a) % 26
            elif cipher_type == "multiplicative":
                val = (val * a) % 26
            elif cipher_type == "affine":
                val = (a * val + b) % 26
            result += chr(val + 65)
        else:
            result += ch
    return result

def decrypt(msg, key, cipher_type):
    a, b = key if isinstance(key, tuple) else (key, 0)
    inv_a = mod_inverse(a)
    if cipher_type == "multiplicative" or cipher_type == "affine":
        if inv_a is None:
            return None
    result = ""
    for ch in msg:
        if ch.isalpha():
            val = ord(ch) - 65
            if cipher_type == "additive":
                val = (val - a) % 26
            elif cipher_type == "multiplicative":
                val = (val * inv_a) % 26
            elif cipher_type == "affine":
                val = (inv_a * (val - b)) % 26
            result += chr(val + 65)
        else:
            result += ch
    return result

def menu():
    message = "I am learning information security"
    msg = clean_msg(message)

    while True:
        print("\n1) Additive cipher (key=20)")
        print("2) Multiplicative cipher (key=15)")
        print("3) Affine cipher (key=(15,20))")
        print("4) Exit")
        choice = input("Select option: ")

        if choice == "1":
            k = 20
            enc = encrypt(msg, k, "additive")
            dec = decrypt(enc, k, "additive")
        elif choice == "2":
            k = 15
            if not mod_inverse(k):
                print("No modular inverse for key, can't decrypt.")
                continue
            enc = encrypt(msg, k, "multiplicative")
            dec = decrypt(enc, k, "multiplicative")
        elif choice == "3":
            k = (15, 20)
            if not mod_inverse(k[0]):
                print("No modular inverse for key 'a', can't decrypt.")
                continue
            enc = encrypt(msg, k, "affine")
            dec = decrypt(enc, k, "affine")
        elif choice == "4":
            break
        else:
            print("Invalid option!")
            continue

        print(f"Original: {msg}")
        print(f"Encrypted: {enc}")
        print(f"Decrypted: {dec}")

if __name__ == "__main__":
    menu()
