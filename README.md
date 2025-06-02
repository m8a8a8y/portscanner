# Advanced Python Port Scanner with Pentesting Hints and OS Detection

A Python-based multi-threaded port scanner that scans a wide range of TCP ports on a target host, identifies open ports, attempts to grab service banners, guesses the target OS based on TTL values, and provides pentesting hints for common services. Results can be saved to a file.

---

## Features

* Scan large port ranges (default: 1–65535)
* Multi-threaded scanning for faster execution
* Basic banner grabbing for open ports
* OS detection using TTL from ICMP ping
* Pentesting hints and references for common services to guide penetration testers where to focus
* Save scan results and hints to an output file
* Configurable timeout and thread count

---

## Requirements

* Python 3.6+
* Internet connection (for references, optional)
* Administrative privileges may be required for ICMP ping on some systems

---

## Installation

Clone the repository or download the files.

```bash
git clone https://github.com/yourusername/advanced-port-scanner.git
cd advanced-port-scanner
```

Install required Python packages (if any). This scanner uses only standard libraries but if you expand, consider installing `python-nmap` or others.

---

## Usage

```bash
python main.py <target> [options]
```

### Arguments

| Option            | Description                           | Default    |
| ----------------- | ------------------------------------- | ---------- |
| `target`          | Target IP address or hostname to scan | (required) |
| `-s`, `--start`   | Start port number                     | 1          |
| `-e`, `--end`     | End port number                       | 65535      |
| `-t`, `--timeout` | Timeout in seconds per port scan      | 1          |
| `-o`, `--output`  | File path to save scan results        | None       |
| `-w`, `--workers` | Number of concurrent scanning threads | 100        |

---

### Example

Scan ports 20 to 100 on `127.0.0.1`, timeout 1 second, save results to `results.txt`, using 200 threads:

```bash
python main.py 127.0.0.1 -s 20 -e 100 -t 1 -o results.txt -w 200
```

---

## Output

* Lists all open ports and their banners (if detected).
* Prints a guessed OS based on TTL values from ping.
* Provides pentesting hints and references for identified services.
* Saves the full report to the specified output file if requested.

---

## Pentesting Hints

The scanner gives guidance on where to look first when pentesting based on the services detected on open ports. For example:

* **Port 22 (SSH)**: Look for weak credentials, outdated versions, or configuration issues.
* **Port 80/443 (HTTP/HTTPS)**: Test for common web vulnerabilities like SQL Injection, XSS, directory traversal.
* **Port 3306 (MySQL)**: Check for default credentials, unpatched vulnerabilities.

Each hint comes with references to trusted resources for further investigation.

---

## Limitations & Notes

* OS detection uses TTL and is only a rough guess.
* Banner grabbing is basic and may not work on all services.
* ICMP ping may require admin privileges on some OSes.
* Scanning all 65535 ports can take time; adjust workers and timeout accordingly.
* This is a reconnaissance tool, **use responsibly and only on authorized targets.**

---

## Future Improvements

* Integrate with `python-nmap` or `nmap` for detailed service/version detection.
* Add support for UDP port scanning.
* More advanced banner grabbing and fingerprinting.
* Output in JSON/HTML for easier parsing/reporting.
* Real-time progress bars or scan status.

---

## References

* [Python socket programming](https://docs.python.org/3/library/socket.html)
* [Python concurrent futures](https://docs.python.org/3/library/concurrent.futures.html)
* [TTL and OS fingerprinting](https://www.tcpipguide.com/free/t_OSFingerprintingandTTLValues.htm)
* [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
* [Exploit Database](https://www.exploit-db.com/)

---

## License

MIT License © 2025 M8a8a8y

