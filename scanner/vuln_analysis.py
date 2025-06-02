PENTEST_HINTS = {
    20: {
        "service": "FTP Data Transfer",
        "hints": [
            "Check for anonymous FTP access.",
            "Look for sensitive file transfer activity.",
        ],
        "references": [
            "https://www.offensive-security.com/metasploit-unleashed/ftp-exploitation/"
        ],
    },
    21: {
        "service": "FTP Control",
        "hints": [
            "Test anonymous login and weak credentials.",
            "Look for writable directories or file upload points.",
            "Enumerate users if possible.",
        ],
        "references": [
            "https://www.offensive-security.com/metasploit-unleashed/ftp-exploitation/",
            "https://www.exploit-db.com/docs/english/18204-ftp-brute-force.txt"
        ],
    },
    22: {
        "service": "SSH",
        "hints": [
            "Attempt brute force using Hydra, Medusa, or Ncrack.",
            "Check for user enumeration vulnerabilities (CVE-2018-15473).",
            "Identify outdated SSH versions for known exploits.",
            "Check for weak SSH keys or default credentials.",
        ],
        "references": [
            "https://www.offensive-security.com/metasploit-unleashed/ssh-login-bruteforce/",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15473"
        ],
    },
    23: {
        "service": "Telnet",
        "hints": [
            "Telnet transmits data unencrypted—intercept with Wireshark.",
            "Try brute forcing credentials.",
            "Telnet is deprecated but often left enabled—test for open Telnet services.",
        ],
        "references": [
            "https://www.offensive-security.com/metasploit-unleashed/telnet/",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0617"
        ],
    },
    25: {
        "service": "SMTP",
        "hints": [
            "Check for open relay vulnerabilities.",
            "Attempt email spoofing and phishing simulations.",
            "Look for default or weak credentials on mail servers.",
        ],
        "references": [
            "https://www.sans.org/white-papers/338/",
            "https://www.offensive-security.com/metasploit-unleashed/smtp/"
        ],
    },
    53: {
        "service": "DNS",
        "hints": [
            "Test for DNS zone transfer vulnerabilities.",
            "Enumerate subdomains using DNS brute forcing.",
            "Look for DNS cache poisoning risks.",
        ],
        "references": [
            "https://www.offensive-security.com/metasploit-unleashed/dns/",
            "https://www.owasp.org/index.php/DNS_Rebinding"
        ],
    },
    80: {
        "service": "HTTP",
        "hints": [
            "Enumerate directories/files with DirBuster, Gobuster, or Nikto.",
            "Scan for outdated CMS or web apps (WordPress, Joomla, Drupal).",
            "Test for injection vulnerabilities: SQLi, XSS, Command Injection.",
            "Look for sensitive data exposure in responses.",
        ],
        "references": [
            "https://portswigger.net/web-security",
            "https://www.owasp.org/index.php/Top_10-2017_A1-Injection"
        ],
    },
    110: {
        "service": "POP3",
        "hints": [
            "Test for cleartext credentials leakage.",
            "Attempt brute force authentication.",
            "Check for open relay if mail server.",
        ],
        "references": [
            "https://www.offensive-security.com/metasploit-unleashed/pop3/",
        ],
    },
    111: {
        "service": "RPCbind / Portmapper",
        "hints": [
            "Check for open RPC services that can be abused for enumeration or DoS.",
            "Attempt to identify exported services.",
        ],
        "references": [
            "https://www.sans.org/reading-room/whitepapers/threats/exploitation-rpc-service-technical-overview-35572"
        ],
    },
    135: {
        "service": "MS RPC",
        "hints": [
            "Look for Windows RPC vulnerabilities.",
            "Attempt enumeration via MS-RPC to discover services and users.",
        ],
        "references": [
            "https://www.rapid7.com/db/modules/auxiliary/scanner/msrpc/endpoint_mapper"
        ],
    },
    139: {
        "service": "NetBIOS/SMB",
        "hints": [
            "Test for SMBv1 vulnerabilities (EternalBlue, CVE-2017-0144).",
            "Enumerate shares and user accounts.",
            "Check for null sessions.",
        ],
        "references": [
            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
            "https://www.offensive-security.com/metasploit-unleashed/smb/"
        ],
    },
    143: {
        "service": "IMAP",
        "hints": [
            "Check for cleartext credential leaks.",
            "Attempt brute forcing login.",
            "Look for open relay or message interception.",
        ],
        "references": [
            "https://www.offensive-security.com/metasploit-unleashed/imap/"
        ],
    },
    161: {
        "service": "SNMP",
        "hints": [
            "Try common community strings: public, private.",
            "Enumerate network devices and configurations.",
            "Look for sensitive information exposure.",
        ],
        "references": [
            "https://www.offensive-security.com/metasploit-unleashed/snmp/"
        ],
    },
    389: {
        "service": "LDAP",
        "hints": [
            "Attempt anonymous binds.",
            "Enumerate users, groups, and configurations.",
            "Look for injection vulnerabilities.",
        ],
        "references": [
            "https://www.offensive-security.com/metasploit-unleashed/ldap/"
        ],
    },
    443: {
        "service": "HTTPS",
        "hints": [
            "Check SSL/TLS version and cipher suites with testssl.sh.",
            "Look for Heartbleed or other SSL vulnerabilities.",
            "Apply same web app tests as HTTP.",
        ],
        "references": [
            "https://testssl.sh/",
            "https://blog.qualys.com/ssllabs/2014/03/04/ssl-server-rating-guide"
        ],
    },
    445: {
        "service": "Microsoft-DS (SMB over TCP)",
        "hints": [
            "Same as port 139 for SMB vulnerabilities.",
            "Check for open shares and null sessions.",
            "Scan for recent exploits (EternalBlue).",
        ],
        "references": [
            "https://www.offensive-security.com/metasploit-unleashed/smb/",
            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"
        ],
    },
    514: {
        "service": "Syslog",
        "hints": [
            "Check if syslog server accepts remote logs (possible log poisoning).",
        ],
        "references": [],
    },
    1433: {
        "service": "Microsoft SQL Server",
        "hints": [
            "Try default or weak credentials.",
            "Look for SQL injection opportunities if app linked.",
            "Check for outdated versions with known exploits.",
        ],
        "references": [
            "https://pentestlab.blog/2017/03/27/mssql/",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2122"
        ],
    },
    1521: {
        "service": "Oracle DB",
        "hints": [
            "Check for default credentials.",
            "Enumerate schemas and users if authenticated.",
            "Test for SQL injection in applications.",
        ],
        "references": [
            "https://pentestlab.blog/2016/11/29/oracle-database-security-assessment/"
        ],
    },
    3306: {
        "service": "MySQL",
        "hints": [
            "Try default and weak credentials.",
            "Enumerate databases and users if accessible.",
            "Check for SQL injection vulnerabilities.",
        ],
        "references": [
            "https://pentestlab.blog/2017/03/27/mysql-security/",
        ],
    },
    3389: {
        "service": "RDP (Remote Desktop)",
        "hints": [
            "Check for weak or default credentials.",
            "Look for open RDP services vulnerable to BlueKeep (CVE-2019-0708).",
            "Use Nmap scripts or Metasploit modules for enumeration.",
        ],
        "references": [
            "https://www.rapid7.com/blog/post/2019/05/14/explaining-bluekeep/",
            "https://www.offensive-security.com/metasploit-unleashed/rdp/"
        ],
    },
    5900: {
        "service": "VNC",
        "hints": [
            "Try default/no password access.",
            "Check for outdated VNC versions.",
            "Intercept VNC traffic if unencrypted.",
        ],
        "references": [
            "https://www.offensive-security.com/metasploit-unleashed/vnc/"
        ],
    },
    8080: {
        "service": "HTTP-Proxy / Alternate HTTP",
        "hints": [
            "Enumerate web services similar to port 80.",
            "Look for proxy misconfigurations and open proxy abuse.",
        ],
        "references": [
            "https://portswigger.net/web-security",
        ],
    },
    # Add more ports and hints as you see fit...
}

def generate_pentest_hints(open_ports):
    results = []
    for port_info in open_ports:
        port = port_info["port"]
        if port in PENTEST_HINTS:
            entry = PENTEST_HINTS[port]
            results.append({
                "port": port,
                "service": entry["service"],
                "hints": entry["hints"],
                "references": entry["references"]
            })
    return results
