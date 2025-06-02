import subprocess
import platform

def detect_os(ip):
    try:
        if platform.system().lower() == "windows":
            ping_cmd = ["ping", "-n", "1", ip]
        else:
            ping_cmd = ["ping", "-c", "1", ip]

        result = subprocess.run(ping_cmd, capture_output=True, text=True)
        if "ttl=" in result.stdout.lower():
            ttl = int(result.stdout.lower().split("ttl=")[-1].split()[0])
            if ttl >= 128:
                return "Windows (TTL ≥ 128)"
            elif ttl >= 64:
                return "Linux/Unix (TTL ≥ 64)"
            else:
                return "Unknown OS (Low TTL)"
        return "Unknown"
    except Exception:
        return "OS Detection Failed"
