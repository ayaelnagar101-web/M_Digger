"""
Module 2: DNS Enumeration
Query DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
"""

import dns.resolver
from colorama import Fore, Style

class DNSEnum:
    def __init__(self, domain):
        self.domain = domain
        self.record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    def run(self):
        """Enumerate all DNS record types"""
        print(f"{Fore.BLUE}[*] Enumerating DNS records for {self.domain}...{Style.RESET_ALL}")
        
        result = {
            "domain": self.domain,
            "records": {}
        }
        
        for record_type in self.record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                records = []
                
                for answer in answers:
                    records.append(str(answer))
                
                if records:
                    result["records"][record_type] = records
                    print(f"  {Fore.GREEN}[+] {record_type} Records: {len(records)} found{Style.RESET_ALL}")
                    
                    # Show first few records
                    for record in records[:5]:
                        print(f"      - {record}")
                    if len(records) > 5:
                        print(f"      ... and {len(records) - 5} more")
                        
            except dns.resolver.NoAnswer:
                print(f"  {Fore.YELLOW}[-] {record_type}: No records found{Style.RESET_ALL}")
            except dns.resolver.NXDOMAIN:
                print(f"  {Fore.RED}[!] Domain {self.domain} does not exist{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"  {Fore.RED}[!] {record_type} query failed: {str(e)}{Style.RESET_ALL}")
        
        return result
