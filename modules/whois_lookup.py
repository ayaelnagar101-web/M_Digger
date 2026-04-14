"""
Module 1: WHOIS Lookup
Query WHOIS database for domain registration information
"""

import whois
from colorama import Fore, Style

class WhoisLookup:
    def __init__(self, domain):
        self.domain = domain
    
    def run(self):
        """Run WHOIS lookup and return structured data"""
        print(f"{Fore.BLUE}[*] Querying WHOIS for {self.domain}...{Style.RESET_ALL}")
        
        result = {
            "domain": self.domain,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "name_servers": [],
            "org": None,
            "country": None,
            "emails": [],
            "privacy_enabled": False
        }
        
        try:
            w = whois.whois(self.domain)
            
            # Check for privacy protection
            if "Domains By Proxy" in str(w) or "Privacy" in str(w) or "REDACTED" in str(w):
                result["privacy_enabled"] = True
                print(f"  {Fore.YELLOW}[!] WHOIS Privacy Protection: ENABLED{Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}[+] WHOIS Privacy Protection: DISABLED{Style.RESET_ALL}")
            
            # Extract registrar
            result["registrar"] = w.registrar
            if w.registrar:
                print(f"  {Fore.GREEN}[+] Registrar: {w.registrar}{Style.RESET_ALL}")
            
            # Extract dates (handle list vs single value)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    result["creation_date"] = w.creation_date[0].isoformat()
                else:
                    result["creation_date"] = w.creation_date.isoformat()
                print(f"  {Fore.GREEN}[+] Created: {result['creation_date']}{Style.RESET_ALL}")
            
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    result["expiration_date"] = w.expiration_date[0].isoformat()
                else:
                    result["expiration_date"] = w.expiration_date.isoformat()
                print(f"  {Fore.GREEN}[+] Expires: {result['expiration_date']}{Style.RESET_ALL}")
            
            # Extract nameservers
            if w.name_servers:
                result["name_servers"] = list(w.name_servers) if isinstance(w.name_servers, list) else [w.name_servers]
                print(f"  {Fore.GREEN}[+] Nameservers: {len(result['name_servers'])} found{Style.RESET_ALL}")
                for ns in result["name_servers"][:3]:  # Show first 3
                    print(f"      - {ns}")
            
            # Extract organization
            result["org"] = w.org
            if w.org:
                print(f"  {Fore.GREEN}[+] Organization: {w.org}{Style.RESET_ALL}")
            
            # Extract country
            result["country"] = w.country
            if w.country:
                print(f"  {Fore.GREEN}[+] Country: {w.country}{Style.RESET_ALL}")
            
            # Extract emails
            if w.emails:
                result["emails"] = list(w.emails) if isinstance(w.emails, list) else [w.emails]
                print(f"  {Fore.GREEN}[+] Contact Emails: {len(result['emails'])} found{Style.RESET_ALL}")
                for email in result["emails"]:
                    print(f"      - {email}")
            
            return result
            
        except Exception as e:
            print(f"  {Fore.RED}[!] WHOIS lookup failed: {str(e)}{Style.RESET_ALL}")
            result["error"] = str(e)
            return result
