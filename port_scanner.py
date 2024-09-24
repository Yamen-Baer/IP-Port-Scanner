import psutil
import socket

# Function to scan active ports on the machine
def scan_active_ports():
    connections = psutil.net_connections()
    active_ports = []
    for conn in connections:
        if conn.status == psutil.CONN_LISTEN or conn.status == psutil.CONN_ESTABLISHED:
            laddr = conn.laddr
            try:
                service = socket.getservbyport(laddr.port)  # Get service name
            except OSError:
                service = "Unknown Service"
            active_ports.append(f"Port: {laddr.port}, Service: {service}")
    return active_ports
