"""
Network Scanner Module - Using Ping Method
Works even when firewall blocks ARP requests
"""

import socket
import subprocess
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.scan_time = None
        
    def get_network_range(self):
        """Automatically detect your network range"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            ip_parts = local_ip.split('.')
            ip_parts[-1] = '0/24'
            network = '.'.join(ip_parts)
            return network, local_ip
        except:
            return '192.168.1.0/24', '192.168.1.1'
    
    def ping_host(self, ip):
        """Ping a single IP address"""
        try:
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '500', ip],
                capture_output=True,
                timeout=2,
                text=True
            )
            if result.returncode == 0:
                if "Reply from" in result.stdout or "bytes=" in result.stdout:
                    return True
            return False
        except:
            return False
    
    def scan_network(self, network_range=None):
        """Scan network using ping"""
        if not network_range:
            network_range, _ = self.get_network_range()
        
        print(f"[*] Scanning network: {network_range} using ping...")
        
        devices = []
        net = ipaddress.ip_network(network_range, strict=False)
        ip_list = [str(ip) for ip in net.hosts()]
        
        if len(ip_list) > 50:
            ip_list = ip_list[:50]
            print(f"[*] Scanning first 50 IP addresses")
        else:
            print(f"[*] Scanning {len(ip_list)} IP addresses...")
        
        print("[*] Sending pings (this may take 10-20 seconds)...")
        active_ips = []
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            results = list(executor.map(self.ping_host, ip_list))
        
        for ip, active in zip(ip_list, results):
            if active:
                active_ips.append(ip)
                print(f"[+] Found: {ip}")
        
        for ip in active_ips:
            device = {
                'ip': ip,
                'mac': 'Unknown (Ping)',
                'vendor': 'Unknown',
                'status': 'Active',
                'ports': [],
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            devices.append(device)
        
        self.devices = devices
        self.scan_time = datetime.now()
        print(f"[*] Scan complete! Found {len(devices)} devices.")
        return devices
    
    def scan_ports(self, ip, ports=None):
        """Scan common ports on a specific device"""
        if ports is None:
            ports = [
                20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 
                139, 143, 443, 445, 993, 995, 1723, 3306, 
                3389, 5432, 5900, 8080, 8443, 27017
            ]
        
        open_ports = []
        print(f"[*] Scanning ports on {ip}...")
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    service = self.get_service_name(port)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'Open'
                    })
                    print(f"[+] Port {port} ({service}) is OPEN")
                sock.close()
            except:
                pass
        
        print(f"[*] Port scan complete. Found {len(open_ports)} open ports.")
        return open_ports
    
    # ============================================================
    # THIS IS THE get_service_name METHOD YOU'RE LOOKING FOR
    # ============================================================
    def get_service_name(self, port):
        """Get service name from port number"""
        services = {
            # File Transfer
            20: 'FTP-Data',
            21: 'FTP',
            69: 'TFTP',
            
            # Remote Access
            22: 'SSH',
            23: 'Telnet',
            3389: 'RDP',
            5900: 'VNC',
            5901: 'VNC-1',
            5800: 'VNC-HTTP',
            
            # Email
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            993: 'IMAPS',
            995: 'POP3S',
            465: 'SMTPS',
            587: 'SMTP-Submit',
            
            # Web
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            8000: 'HTTP-Alt',
            8888: 'HTTP-Alt',
            
            # Database
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB',
            6379: 'Redis',
            1433: 'MSSQL',
            1521: 'Oracle',
            9042: 'Cassandra',
            
            # Windows Services
            135: 'RPC',
            139: 'NetBIOS',
            445: 'SMB',
            464: 'Kerberos',
            636: 'LDAPS',
            3268: 'LDAP-GC',
            3269: 'LDAP-GC-SSL',
            
            # DNS & Network
            53: 'DNS',
            111: 'RPCbind',
            123: 'NTP',
            161: 'SNMP',
            162: 'SNMP-Trap',
            1723: 'PPTP',
            5000: 'UPnP',
            5060: 'SIP',
            5061: 'SIP-TLS',
            
            # Development
            8089: 'Splunk',
            9200: 'Elasticsearch',
            9300: 'Elasticsearch-Transport',
        }
        return services.get(port, f'Port {port}')
    # ============================================================
    # END OF get_service_name METHOD
    # ============================================================
    
    def get_stats(self):
        """Get statistics about the current scan"""
        if not self.devices:
            return {'total': 0, 'unknown': 0, 'ports_total': 0}
        
        total = len(self.devices)
        unknown = sum(1 for d in self.devices if d['vendor'] == 'Unknown' or d['vendor'] == 'Unknown Device')
        total_ports = sum(len(d.get('ports', [])) for d in self.devices)
        
        return {
            'total': total,
            'unknown': unknown,
            'ports_total': total_ports,
            'known': total - unknown
        }
     # ============================================================
        # vULNERABILITY DETECTION PLACEHOLDER
        # ============================================================

        def check_vulnerabilities(self, ip, port, service):
            """Check for known vulnerabilities"""
    vulnerabilities = {
        445: "⚠️ HIGH RISK: SMB port exposed! Ransomware risk!",
        135: "⚠️ MEDIUM RISK: RPC exposed! Remote code execution possible!",
        23: "⚠️ HIGH RISK: Telnet exposed! Passwords sent in plaintext!",
        21: "⚠️ MEDIUM RISK: FTP exposed! Passwords sent in plaintext!",
        3306: "⚠️ MEDIUM RISK: MySQL exposed! Database attacks possible!",
        5432: "⚠️ MEDIUM RISK: PostgreSQL exposed! Data theft possible!",
        8080: "⚠️ MEDIUM RISK: Web admin panel exposed! Brute force risk!",
        3389: "⚠️ HIGH RISK: RDP exposed! Remote access attacks!"
    }
    return vulnerabilities.get(port, "✅ No known critical vulnerabilities")
