import socket

target = ("127.0.0.1", 50011)   
payload = b"RESET"              

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
