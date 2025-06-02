from concurrent.futures import ThreadPoolExecutor
from .scanner import scan_port

def threaded_scan(ip, start_port, end_port, max_threads=100):
    open_ports = []

    def handle_result(port):
        result = scan_port(ip, port)
        if result:
            open_ports.append(result)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(handle_result, port)

    return open_ports
