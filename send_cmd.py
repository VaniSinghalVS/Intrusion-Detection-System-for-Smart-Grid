# send_cmd.py
import socket

target = ("127.0.0.1", 50011)   # local host & arbitrary port
payload = b"RESET"              # sensitive command

try:
    s = socket.socket()
    s.settimeout(0.5)
    s.connect(target)
    s.sendall(payload)
except Exception:
    pass
finally:
    try:
        s.close()
    except:
        pass

print("sent RESET")
