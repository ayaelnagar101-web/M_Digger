"""
Module 5: HTTP Header Inspection
Analyze HTTP response headers and audit security headers
"""

import requests
from colorama import Fore, Style

class HTTPHeaders:
    def __init__(self, domain):
        self.domain = domain
        
        # Security headers to check (from lab PDF page 9)
        self.security_headers = {
            "Strict-Transport-Security": "Forces HTTPS, prevents downgrade attacks",
            "Content-Security-Policy": "Prevents XSS and data injection attacks",
            "X-Frame-Options": "Prevents clickjacking via iframe embedding",
            "X-Content-Type-Options": "Prevents MIME-type sniffing attacks",
            "Referrer-Policy": "Controls what referrer info is sent to other sites",
            "Permissions-Policy": "Controls browser feature access (camera, mic, etc.)"
        }
    
    def run(self):
        """Fetch headers and audit security"""
        print(f"{Fore.BLUE}[*] Fetching HTTP headers from {self.domain}...{Style.RESET_ALL}")
        
        result = {
            "domain": self.domain,
            "url": f"https://{self.domain}",
            "headers": {},
            "security_audit": {},
            "server_info": {}
        }
        
        try:
            # Try HTTPS first
            response = requests.get(f"https://{self.domain}", timeout=10, allow_redirects=True)
            result["url"] = response.url
            
            # Store all headers
            result["headers"] = dict(response.headers)
            
            # Extract server information
            if 'Server' in response.headers:
                result["server_info"]["server"] = response.headers['Server']
                print(f"  {Fore.GREEN}[+] Server: {response.headers['Server']}{Style.RESET_ALL}")
            
            if 'X-Powered-By' in response.headers:
                result["server_info"]["powered_by"] = response.headers['X-Powered-By']
                print(f"  {Fore.YELLOW}[!] X-Powered-By: {response.headers['X-Powered-By']}{Style.RESET_ALL}")
            
            # Audit security headers
            print(f"\n  {Fore.CYAN}Security Header Audit:{Style.RESET_ALL}")
            for header, description in self.security_headers.items():
                if header in response.headers:
                    result["security_audit"][header] = {
                        "status": "PRESENT",
                        "value": response.headers[header],
                        "description": description
                    }
                    print(f"    {Fore.GREEN}[✓] {header}: PRESENT{Style.RESET_ALL}")
                else:
                    result["security_audit"][header] = {
                        "status": "MISSING",
                        "value": None,
                        "description": description
                    }
                    print(f"    {Fore.RED}[✗] {header}: MISSING{Style.RESET_ALL}")
            
            return result
            
        except requests.exceptions.SSLError:
            # Fallback to HTTP if HTTPS fails
            try:
                response = requests.get(f"http://{self.domain}", timeout=10, allow_redirects=True)
                result["url"] = response.url
                result["headers"] = dict(response.headers)
                print(f"  {Fore.YELLOW}[!] HTTPS failed, using HTTP{Style.RESET_ALL}")
                return result
            except Exception as e:
                print(f"  {Fore.RED}[!] HTTP request failed: {str(e)}{Style.RESET_ALL}")
                result["error"] = str(e)
                return result
        except Exception as e:
            print(f"  {Fore.RED}[!] HTTP request failed: {str(e)}{Style.RESET_ALL}")
            result["error"] = str(e)
            return result
