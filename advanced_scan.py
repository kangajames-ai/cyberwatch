"""
Advanced Port Scanner - Scans 1000+ ports
Use this to find ALL open ports on your router
"""

import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port):
    """Test if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0
    except:
        return port, False

def scan_ports(ip):
    """Scan ports 1-1000 on an IP"""
    print(f"Scanning {ip}...")
    open_ports = []
    
    # Scan 1000 ports
    ports = range(1, 1001)
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(lambda p: scan_port(ip, p), ports))
    
    for port, is_open in results:
        if is_open:
            open_ports.append(port)
            print(f"[+] Port {port} is OPEN")
    
    return open_ports

if __name__ == "__main__":
    target = "192.168.80.1"  # Your router
    print("=" * 50)
    print("ADVANCED PORT SCAN")
    print("=" * 50)
    
    open_ports = scan_ports(target)
    
    print("\n" + "=" * 50)
    print(f"FOUND {len(open_ports)} OPEN PORTS:")
    print(open_ports)
    print("=" * 50)