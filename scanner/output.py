def save_to_file(open_ports, os_guess, vulns, filename):
    with open(filename, 'w') as f:
        f.write(f"Possible OS: {os_guess}\n\nOpen Ports:\n")
        for port in open_ports:
            f.write(f"- Port {port['port']} | Banner: {port['banner']}\n")

        if vulns:
            f.write("\nPotential Vulnerabilities:\n")
            for v in vulns:
                f.write(f"- Port {v['port']}: {v['vuln']}\n")
