import socket, time

target = ("127.0.0.1", 50010)  
payload = b"CMD:READ"          

for i in range(3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(target)
        s.sendall(payload)
        try:
            s.recv(64)
        except:
            pass
    except Exception:
        pass
    finally:
        try:
            s.close()
        except:
            pass
    print("sent", i+1)
    time.sleep(0.8)
