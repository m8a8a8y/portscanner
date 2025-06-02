import socket

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    banner = sock.recv(1024).decode().strip()
                except:
                    banner = "Unknown"
                print(f"[OPEN] Port {port} - Banner: {banner}")
                return {"port": port, "banner": banner}
    except:
        return None
