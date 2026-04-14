"""
Advanced Port Scanner with Service Detection & Banner Grabbing
"""
import socket
import concurrent.futures
import time
import random
from colorama import Fore, Style

class PortScanner:
    """Threaded TCP port scanner with service detection"""
    
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        111: 'RPC',
        135: 'RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1723: 'PPTP',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    
    def __init__(self, target, ports=None, threads=50):
        self.target = target
        self.ports = ports or list(self.COMMON_PORTS.keys())
        self.threads = threads
        self.stealth_mode = False
        self.delay = 0
        
    def set_stealth_mode(self, enabled=True):
        """Enable stealth scanning with delays"""
        self.stealth_mode = enabled
        self.delay = random.uniform(0.5, 2.0) if enabled else 0
    
    def scan(self):
        """Perform port scan"""
        print(f"{Fore.BLUE}[*] Scanning {len(self.ports)} ports on {self.target}...{Style.RESET_ALL}")
        print(f"  Stealth Mode: {'ON' if self.stealth_mode else 'OFF'}")
        
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self._scan_port, port): port 
                for port in self.ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result['open']:
                        open_ports.append(result)
                        print(f"  {Fore.GREEN}[OPEN] {port}/{result['protocol']} - {result['service']}{Style.RESET_ALL}")
                        
                        # Show banner snippet if available
                        if result.get('banner'):
                            banner_preview = result['banner'][:50].replace('\n', ' ')
                            print(f"      {Fore.CYAN}Banner: {banner_preview}...{Style.RESET_ALL}")
                    
                    # Stealth delay
                    if self.stealth_mode:
                        time.sleep(self.delay)
                        
                except Exception as e:
                    print(f"  {Fore.RED}[!] Error scanning port {port}: {e}{Style.RESET_ALL}")
        
        print(f"  {Fore.GREEN}[+] Scan complete: {len(open_ports)} ports open{Style.RESET_ALL}")
        return open_ports
    
    def _scan_port(self, port):
        """Scan individual port with banner grab"""
        result = {
            'port': port,
            'protocol': 'tcp',
            'service': self.COMMON_PORTS.get(port, 'Unknown'),
            'open': False,
            'banner': None
        }
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            # Attempt connection
            connect_result = sock.connect_ex((self.target, port))
            
            if connect_result == 0:
                result['open'] = True
                
                # Try to grab banner
                try:
                    # Send probe based on service
                    if port == 80 or port == 443 or port == 8080 or port == 8443:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    elif port == 21:  # FTP
                        pass  # FTP sends banner automatically
                    elif port == 22:  # SSH
                        pass  # SSH sends banner automatically
                    elif port == 25:  # SMTP
                        sock.send(b"EHLO test.com\r\n")
                    
                    banner = sock.recv(1024)
                    result['banner'] = banner.decode('utf-8', errors='ignore').strip()
                    
                    # Update service based on banner
                    if 'SSH' in result['banner']:
                        result['service'] = 'SSH'
                    elif 'FTP' in result['banner']:
                        result['service'] = 'FTP'
                    elif 'SMTP' in result['banner']:
                        result['service'] = 'SMTP'
                        
                except socket.timeout:
                    pass
                except:
                    pass
            
            sock.close()
            
        except Exception as e:
            pass
        
        return result
