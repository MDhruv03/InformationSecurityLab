# 1. Write server and client scripts where the client sends a message in multiple parts to
# the server, the server reassembles the message, computes the hash of the reassembled
# message, and sends this hash back to the client. The client then verifies the integrity of
# the message by comparing the received hash with the locally computed hash of the
# original message.


# ============================================================
# Single-File Demo: Multi-Part Message Transmission with Hash Integrity
# ============================================================

import socket
import hashlib
import threading
import time

# -------------------------------
# Configuration
# -------------------------------
HOST = '127.0.0.1'
PORT = 65432

# -------------------------------
# Helper Function: Compute SHA-256 Hash
# -------------------------------
def compute_hash(data_bytes):
    """
    Computes SHA-256 hash for given bytes.
    Returns hexadecimal digest string.
    """
    sha = hashlib.sha256()
    sha.update(data_bytes)
    return sha.hexdigest()

# -------------------------------
# Server Function
# -------------------------------
def server():
    """
    Server receives a message in multiple parts,
    reassembles it, computes hash, and sends the hash back.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[SERVER] Listening on {HOST}:{PORT}...")

        conn, addr = s.accept()
        with conn:
            print(f"[SERVER] Connected by {addr}")

            # Reassemble the message from multiple parts
            full_message = b""
            while True:
                part = conn.recv(16)  # Receive message in small chunks (16 bytes)
                if not part:          # No more data, transmission complete
                    break
                full_message += part

            print(f"[SERVER] Reassembled message: {full_message.decode()}")

            # Compute hash of the complete message
            message_hash = compute_hash(full_message)
            print(f"[SERVER] Computed hash: {message_hash}")

            # Send hash back to client
            conn.sendall(message_hash.encode())
            print("[SERVER] Hash sent back to client.")

# -------------------------------
# Client Function
# -------------------------------
def client(message):
    """
    Client sends a message in multiple parts,
    receives the server's hash, and verifies integrity.
    """
    time.sleep(1)  # Ensure server starts first
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        print(f"[CLIENT] Sending message in parts: '{message}'")
        # Send message in small chunks (simulate partial transmission)
        for i in range(0, len(message), 5):  # 5 characters per chunk
            chunk = message[i:i+5].encode()
            s.sendall(chunk)
            time.sleep(0.1)  # Optional delay to simulate network lag

        s.shutdown(socket.SHUT_WR)  # Indicate end of transmission

        # Compute local hash for integrity verification
        local_hash = compute_hash(message.encode())
        print(f"[CLIENT] Local hash: {local_hash}")

        # Receive hash computed by server
        received_hash = s.recv(1024).decode()
        print(f"[CLIENT] Hash received from server: {received_hash}")

        # Verify integrity
        if local_hash == received_hash:
            print("[CLIENT] ✅ Data integrity verified! No tampering detected.")
        else:
            print("[CLIENT] ❌ Data integrity check failed! Message may have been corrupted.")

# -------------------------------
# Main Execution
# -------------------------------
if __name__ == "__main__":
    # Message to send
    message_to_send = "Hello, this is a multi-part message for integrity verification!"

    # Start server in a separate thread
    server_thread = threading.Thread(target=server, daemon=True)
    server_thread.start()

    # Start client in main thread
    client(message_to_send)

    # Wait for server thread to finish (optional)
    server_thread.join()