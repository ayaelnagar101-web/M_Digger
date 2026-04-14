"""
Subdomain Enumeration with DNS Resolution
"""
import dns.resolver
import concurrent.futures
import time
import random
from colorama import Fore, Style

class SubdomainEnumerator:
    """Brute-force subdomain discovery"""
    
    def __init__(self, domain, wordlist_path, threads=30):
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.stealth_mode = False
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        
    def set_stealth_mode(self, stealth_requester):
        """Enable stealth with delays"""
        self.stealth_mode = True
    
    def enumerate(self):
        """Perform subdomain enumeration"""
        print(f"{Fore.BLUE}[*] Enumerating subdomains for {self.domain}...{Style.RESET_ALL}")
        
        # Load wordlist
        try:
            with open(self.wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            print(f"  Loaded {len(words)} words")
        except FileNotFoundError:
            print(f"  {Fore.RED}[!] Wordlist not found{Style.RESET_ALL}")
            return []
        
        discovered = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._resolve_subdomain, f"{word}.{self.domain}"): word
                for word in words
            }
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        discovered.append(result)
                        print(f"  {Fore.GREEN}[FOUND] {result['subdomain']} → {', '.join(result['ips'])}{Style.RESET_ALL}")
                    
                    # Stealth delay
                    if self.stealth_mode:
                        time.sleep(random.uniform(0.1, 0.3))
                        
                except Exception:
                    pass
        
        print(f"  {Fore.GREEN}[+] Found {len(discovered)} subdomains{Style.RESET_ALL}")
        return discovered
    
    def _resolve_subdomain(self, subdomain):
        """Resolve subdomain to IP"""
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            ips = [str(answer) for answer in answers]
            
            return {
                'subdomain': subdomain,
                'ips': ips
            }
        except:
            return None
