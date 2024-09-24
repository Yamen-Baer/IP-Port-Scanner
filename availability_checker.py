import socket
import ipaddress

# Check if a given IP is available (not in use)
def check_ip_availability(ip):
    try:
        socket.gethostbyaddr(ip)
        return False  # IP is in use
    except socket.herror:
        return True  # IP is not in use

# Check if a given port is available on localhost
def check_port_availability(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        result = s.connect_ex(('localhost', port))
        return result != 0  # True if port is available, False if in use
