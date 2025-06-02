import argparse
import socket
import concurrent.futures
from scanner.vuln_analysis import generate_pentest_hints

def scan_port(host, port, timeout=1):
    """
    Attempts to connect to a port on a host.
    Returns tuple: (port, banner or None)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode(errors='ignore').strip()
                except Exception:
                    banner = None
                return (port, banner)
    except Exception:
        return None
    return None

def detect_os(ttl):
    """
    Simple OS guess based on TTL value (from ICMP ping).
    Typical TTL values:
    - Linux/Unix: 64
    - Windows: 128
    - Cisco/Network devices: 255
    """
    if ttl is None:
        return "Unknown"
    elif ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Network Device (Cisco, etc.)"
    else:
        return "Unknown"

def get_ttl(host):
    """
    Sends a ping and retrieves TTL from the ICMP reply.
    Note: Requires admin privileges on some OSes.
    """
    import platform
    import subprocess
    param = '-n' if platform.system().lower()=='windows' else '-c'
    try:
        ping = subprocess.run(['ping', param, '1', host], capture_output=True, text=True)
        output = ping.stdout
        if platform.system().lower() == 'windows':
            # TTL=xxx in response line
            import re
            match = re.search(r"TTL=(\d+)", output)
            if match:
                return int(match.group(1))
        else:
            # Look for ttl=xxx in Unix ping output
            import re
            match = re.search(r"ttl=(\d+)", output)
            if match:
                return int(match.group(1))
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner with Pentest Hints and OS detection")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=65535, help="End port (default: 65535)")
    parser.add_argument("-t", "--timeout", type=int, default=1, help="Timeout for each port scan in seconds (default: 1)")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Number of concurrent threads (default: 100)")
    args = parser.parse_args()

    print(f"Scanning {args.target} from port {args.start} to {args.end} with timeout {args.timeout}s...")

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = []
        for port in range(args.start, args.end + 1):
            futures.append(executor.submit(scan_port, args.target, port, args.timeout))

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                port, banner = result
                print(f"[+] Port {port} is open. Banner: {banner if banner else 'N/A'}")
                open_ports.append({"port": port, "banner": banner})

    # OS detection
    ttl = get_ttl(args.target)
    os_guess = detect_os(ttl)
    print(f"\nOS Guess based on TTL ({ttl}): {os_guess}")

    # Generate pentesting hints
    hints = generate_pentest_hints(open_ports)
    if hints:
        print("\nPentesting Hints:")
        for hint in hints:
            print(f"\nPort {hint['port']} ({hint['service']}):")
            for i, h in enumerate(hint['hints'], 1):
                print(f"  {i}. {h}")
            if hint['references']:
                print("  References:")
                for ref in hint['references']:
                    print(f"   - {ref}")

    # Save output if requested
    if args.output:
        with open(args.output, "w") as f:
            f.write(f"Scan results for {args.target}\n\n")
            f.write(f"OS Guess based on TTL ({ttl}): {os_guess}\n\n")
            f.write("Open Ports:\n")
            for port_info in open_ports:
                f.write(f"- Port {port_info['port']}: Banner: {port_info['banner'] if port_info['banner'] else 'N/A'}\n")
            if hints:
                f.write("\nPentesting Hints:\n")
                for hint in hints:
                    f.write(f"\nPort {hint['port']} ({hint['service']}):\n")
                    for i, h in enumerate(hint['hints'], 1):
                        f.write(f"  {i}. {h}\n")
                    if hint['references']:
                        f.write("  References:\n")
                        for ref in hint['references']:
                            f.write(f"   - {ref}\n")
        print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main()
