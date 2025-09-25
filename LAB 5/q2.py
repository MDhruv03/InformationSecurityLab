# 2. Using socket programming in Python, demonstrate the application of hash functions
# for ensuring data integrity during transmission over a network. Write server and client
# scripts where the server computes the hash of received data and sends it back to the
# client, which then verifies the integrity of the data by comparing the received hash with
# the locally computed hash. Show how the hash verification detects data corruption
# or tampering during transmission.

# ============================================================
# Single-File Demo: Socket Programming + Hash for Data Integrity
# ============================================================

import socket
import hashlib
import threading
import time

# -------------------------------
# Configuration
# -------------------------------
HOST = '127.0.0.1'  # Localhost
PORT = 65432        # Port to use

# -------------------------------
# Helper Function: Compute Hash
# -------------------------------
def compute_hash(data):
    """
    Compute SHA-256 hash of the input data.
    Returns hexadecimal string.
    """
    sha = hashlib.sha256()
    sha.update(data)
    return sha.hexdigest()

# -------------------------------
# Server Function
# -------------------------------
def server():
    """
    Server listens for incoming client connections,
    receives data, computes hash, and sends hash back.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[SERVER] Listening on {HOST}:{PORT}...")
        conn, addr = s.accept()
        with conn:
            print(f"[SERVER] Connected by {addr}")
            data = conn.recv(1024)
            if not data:
                print("[SERVER] No data received.")
                return
            print(f"[SERVER] Received data: {data.decode()}")
            data_hash = compute_hash(data)
            print(f"[SERVER] Computed hash: {data_hash}")
            conn.sendall(data_hash.encode())
            print("[SERVER] Hash sent back to client.")

# -------------------------------
# Client Function
# -------------------------------
def client(message):
    """
    Client connects to server, sends message, computes local hash,
    receives server hash, and verifies data integrity.
    """
    time.sleep(1)  # Wait for server to start
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[CLIENT] Sending message: {message}")
        s.sendall(message.encode())
        local_hash = compute_hash(message.encode())
        print(f"[CLIENT] Local hash: {local_hash}")
        received_hash = s.recv(1024).decode()
        print(f"[CLIENT] Hash received from server: {received_hash}")
        if local_hash == received_hash:
            print("[CLIENT] ✅ Data integrity verified! No tampering detected.")
        else:
            print("[CLIENT] ❌ Data integrity check failed! Data may have been tampered or corrupted.")

# -------------------------------
# Main Execution
# -------------------------------
if __name__ == "__main__":
    # Message to send
    message_to_send = "Hello, this is a test message for integrity check."

    # Start server in a separate thread
    server_thread = threading.Thread(target=server, daemon=True)
    server_thread.start()

    # Start client
    client(message_to_send)

    # Wait for server thread to finish (optional)
    server_thread.join()