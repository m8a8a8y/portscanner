import time
import socket
import re

def get_scan_time(start=None):
    if not start:
        return time.time()
    return time.time() - start

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return host
