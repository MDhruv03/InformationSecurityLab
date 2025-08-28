import string

def generate_key_matrix(key):
    key = key.upper().replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix = []
    used = set()

    for char in key:
        if char in alphabet and char not in used:
            matrix.append(char)
            used.add(char)
    for char in alphabet:
        if char not in used:
            matrix.append(char)
            used.add(char)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def prepare_text(text):
    text = text.upper().replace("J", "I")
    text = "".join(ch for ch in text if ch.isalpha())
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else "X"
        if a == b:
            pairs.append(a + "X")
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    if len(pairs[-1]) == 1:
        pairs[-1] += "X"
    return pairs

def find_position(matrix, char):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None

def playfair_encrypt(plaintext, key):
    matrix = generate_key_matrix(key)
    pairs = prepare_text(plaintext)
    cipher = ""
    for a, b in pairs:
        ra, ca = find_position(matrix, a)
        rb, cb = find_position(matrix, b)
        if ra == rb:
            cipher += matrix[ra][(ca+1)%5]
            cipher += matrix[rb][(cb+1)%5]
        elif ca == cb:
            cipher += matrix[(ra+1)%5][ca]
            cipher += matrix[(rb+1)%5][cb]
        else:
            cipher += matrix[ra][cb]
            cipher += matrix[rb][ca]
    return cipher

key = "GUIDANCE"
plaintext = "The key is hidden under the door pad"

ciphertext = playfair_encrypt(plaintext, key)
print("Playfair cipher:", ciphertext)