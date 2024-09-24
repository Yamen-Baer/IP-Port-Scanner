import psutil
import socket

# Function to scan active IPs on the machine
def scan_active_ips():
    addrs = psutil.net_if_addrs()
    active_ips = []
    for interface, snics in addrs.items():
        for snic in snics:
            if snic.family == socket.AF_INET:  # Only consider IPv4
                active_ips.append(snic.address)
    return active_ips

# Helper function to resolve hostname for an IP address
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout):
        return "Unknown Host"
