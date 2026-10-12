import socket
def grab_banner(target, port, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        if port in (80, 8080, 8000, 8008, 8888):
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            sock.sendall(request.encode())
        else:
            sock.sendall(b"\r\n")
        banner =  sock.recv(1024)
        if not banner:
            return None
        return banner.decode("utf-8", errors="ignore").strip()
    except (socket.timeout, socket.error):
        return None
    finally:
        sock.close()