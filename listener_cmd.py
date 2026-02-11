# listener_cmd.py
import socket

HOST = "127.0.0.1"
PORT = 50011

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)
print("Listening for connections on port", PORT)

while True:
    conn, addr = s.accept()
    data = conn.recv(4096)
    print("Received from", addr, ":", data)
    try:
        conn.sendall(b"OK")
    except:
        pass
    conn.close()
