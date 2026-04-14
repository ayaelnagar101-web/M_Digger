"""
Service Banner Grabbing with CVE Correlation
"""
import socket
import json
import requests
from colorama import Fore, Style

class BannerGrabber:
    """Grab and analyze service banners"""
    
    def __init__(self, target, open_ports):
        self.target = target
        self.open_ports = open_ports
        self.cve_cache = {}
    
    def grab(self):
        """Grab banners from all open ports"""
        print(f"{Fore.BLUE}[*] Grabbing banners from {len(self.open_ports)} ports...{Style.RESET_ALL}")
        
        results = []
        
        for port_info in self.open_ports:
            port = port_info['port']
            
            banner_data = self._grab_port_banner(port)
            
            if banner_data:
                # Check for CVEs
                if banner_data.get('version'):
                    cves = self._check_cves(banner_data['service'], banner_data['version'])
                    if cves:
                        banner_data['cves'] = cves
                        print(f"  {Fore.YELLOW}[!] Port {port}: {len(cves)} CVEs found{Style.RESET_ALL}")
                
                results.append(banner_data)
        
        return results
    
    def _grab_port_banner(self, port):
        """Grab banner from specific port"""
        result = {
            'port': port,
            'service': None,
            'banner': None,
            'version': None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target, port))
            
            # Send appropriate probe
            if port in [80, 443, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 22:
                pass  # SSH sends banner
            elif port == 21:
                pass  # FTP sends banner
            elif port == 3306:
                pass  # MySQL sends banner
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            result['banner'] = banner.strip()
            
            # Parse version
            result['service'] = self._identify_service(banner, port)
            result['version'] = self._extract_version(banner)
            
            sock.close()
            
        except:
            pass
        
        return result
    
    def _identify_service(self, banner, port):
        """Identify service from banner"""
        banner_lower = banner.lower()
        
        if 'ssh' in banner_lower:
            return 'SSH'
        elif 'ftp' in banner_lower:
            return 'FTP'
        elif 'mysql' in banner_lower:
            return 'MySQL'
        elif 'apache' in banner_lower:
            return 'Apache'
        elif 'nginx' in banner_lower:
            return 'Nginx'
        elif 'iis' in banner_lower:
            return 'IIS'
        else:
            return 'Unknown'
    
    def _extract_version(self, banner):
        """Extract version from banner using regex"""
        import re
        
        patterns = [
            r'(\d+\.\d+(?:\.\d+)?)',  # Generic version
            r'Apache/(\d+\.\d+\.\d+)',
            r'nginx/(\d+\.\d+\.\d+)',
            r'OpenSSH[_-](\d+\.\d+[^\s]*)',
            r'MySQL (\d+\.\d+\.\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _check_cves(self, service, version):
        """Check for CVEs (simplified - would use NVD API in production)"""
        # This is a simplified check - in production, query NVD API
        known_vulnerable = {
            'Apache': {'2.4.49': ['CVE-2021-41773'], '2.4.50': ['CVE-2021-42013']},
            'OpenSSH': {'7.4': ['CVE-2018-15473']},
            'Nginx': {'1.20.0': ['CVE-2021-23017']}
        }
        
        if service in known_vulnerable:
            for vuln_version, cves in known_vulnerable[service].items():
                if version and version.startswith(vuln_version):
                    return cves
        
        return []
