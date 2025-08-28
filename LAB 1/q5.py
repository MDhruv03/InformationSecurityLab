def caesar_decrypt(ciphertext, shift):
    plaintext = ''
    for char in ciphertext:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((ord(char) - offset - shift) % 26 + offset)
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext

# Given ciphertext and known Caesar shift of +4
ciphertext = "XVIEWYWI"
shift = 4

decrypted = caesar_decrypt(ciphertext, shift)
print("Decrypted message:", decrypted)