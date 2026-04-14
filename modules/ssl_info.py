"""
Module 3: SSL Certificate Analysis
Extract SSL certificate details and Subject Alternative Names (SANs)
"""

import ssl
import socket
from datetime import datetime
from colorama import Fore, Style

class SSLInfo:
    def __init__(self, domain, port=443):
        self.domain = domain
        self.port = port
    
    def run(self):
        """Retrieve and parse SSL certificate"""
        print(f"{Fore.BLUE}[*] Retrieving SSL certificate from {self.domain}:{self.port}...{Style.RESET_ALL}")
        
        result = {
            "domain": self.domain,
            "port": self.port,
            "subject": {},
            "issuer": {},
            "valid_from": None,
            "valid_until": None,
            "sans": [],
            "wildcard": False
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((self.domain, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
            
            # Parse subject
            for item in cert.get('subject', []):
                for key, value in item:
                    result["subject"][key] = value
            
            # Parse issuer
            for item in cert.get('issuer', []):
                for key, value in item:
                    result["issuer"][key] = value
            
            # Parse dates
            if 'notBefore' in cert:
                result["valid_from"] = cert['notBefore']
                print(f"  {Fore.GREEN}[+] Valid From: {result['valid_from']}{Style.RESET_ALL}")
            
            if 'notAfter' in cert:
                result["valid_until"] = cert['notAfter']
                print(f"  {Fore.GREEN}[+] Valid Until: {result['valid_until']}{Style.RESET_ALL}")
            
            # Extract Subject Alternative Names (SANs)
            for ext in cert.get('subjectAltName', []):
                if ext[0] == 'DNS':
                    result["sans"].append(ext[1])
            
            # Check for wildcard certificate
            for san in result["sans"]:
                if san.startswith('*.'):
                    result["wildcard"] = True
                    break
            
            # Display results
            print(f"  {Fore.GREEN}[+] Issuer: {result['issuer'].get('organizationName', 'Unknown')}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}[+] SANs Found: {len(result['sans'])}{Style.RESET_ALL}")
            
            if result["wildcard"]:
                print(f"  {Fore.YELLOW}[!] Wildcard Certificate: YES{Style.RESET_ALL}")
            
            # Show first 10 SANs
            for san in result["sans"][:10]:
                print(f"      - {san}")
            if len(result["sans"]) > 10:
                print(f"      ... and {len(result['sans']) - 10} more")
            
            return result
            
        except socket.gaierror:
            print(f"  {Fore.RED}[!] Failed to resolve {self.domain}{Style.RESET_ALL}")
            result["error"] = "DNS resolution failed"
            return result
        except ConnectionRefusedError:
            print(f"  {Fore.RED}[!] Connection refused on port {self.port}{Style.RESET_ALL}")
            result["error"] = "Connection refused"
            return result
        except Exception as e:
            print(f"  {Fore.RED}[!] SSL certificate retrieval failed: {str(e)}{Style.RESET_ALL}")
            result["error"] = str(e)
            return result
