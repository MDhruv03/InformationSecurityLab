# server.py
import socket
import hashlib
from Crypto.Util.number import bytes_to_long

# --- SERVER LOGIC ---
HOST = "127.0.0.1"
PORT = 65433

# A helper function to hash a message. Both client and server must use the same one.
def hash_message(msg: bytes):
    return bytes_to_long(hashlib.sha256(msg).digest())

# Verifies a signature using the sender's public key.
def verify(msg: bytes, signature: int, public_key: tuple):
    n, e = public_key
    # Hash the message to get the expected value.
    msg_hash = hash_message(msg)
    # Decrypt the signature with the public key.
    hash_from_signature = pow(signature, e, n)
    # If they match, the signature is valid.
    return msg_hash == hash_from_signature

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening on {HOST}:{PORT}...")
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        
        # 1. Receive the client's public key (n, then e).
        n_bytes = conn.recv(256) # Assuming a 2048-bit key, n is 256 bytes
        e_bytes = conn.recv(16)
        client_n = int.from_bytes(n_bytes, 'big')
        client_e = int.from_bytes(e_bytes, 'big')
        client_public_key = (client_n, client_e)
        print("Received public key from client.")
        
        # 2. Receive the message.
        message = conn.recv(1024)
        
        # 3. Receive the signature.
        signature_bytes = conn.recv(256)
        signature = int.from_bytes(signature_bytes, 'big')
        print("Received message and signature.")
        
        # 4. Verify the signature using the client's public key.
        is_valid = verify(message, signature, client_public_key)
        
        # 5. Send the verification result back to the client.
        if is_valid:
            print("Signature is VALID.")
            conn.sendall(b"VERIFIED")
        else:
            print("Signature is INVALID.")
            conn.sendall(b"FAILED")