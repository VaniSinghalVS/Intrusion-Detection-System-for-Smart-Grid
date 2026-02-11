import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
target_ip = "127.0.0.1"
target_port = 9999   # change if your IDS listens on another port

print("Simulating DoS attack...")

for i in range(200):
    msg = f"dos_packet_{i}".encode()
    sock.sendto(msg, (target_ip, target_port))
    time.sleep(0.01)

print("Simulation complete.")
