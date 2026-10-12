import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def resolve_target(target):
    """
    Resolve a hostname or IP address to an IPv4 address.
    """
    try:
        ip_address = socket.gethostbyname(target)
        return ip_address

    except socket.gaierror:
        raise ValueError(f"Unable to resolve target: {target}")


def scan_port(target, port, timeout=1):
    """
    Scan a single TCP port.

    Returns:
        port number if open
        None if closed or unreachable
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            return port

        return None
    except socket.error:
        return None

    finally:
        sock.close()


def scan_ports(target, start_port, end_port, max_threads=100):
    """
    Scan a range of TCP ports using multiple threads.

    Returns:
        List of open ports
    """
    open_ports = []
    ports = range(start_port, end_port + 1)
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port): port
            for port in ports
        }
        for future in as_completed(future_to_port):

            result = future.result()

            if result is not None:
                open_ports.append(result)
    return sorted(open_ports)