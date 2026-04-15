"""
Working Subdomain Enumeration using multiple sources
"""
import requests
import dns.resolver
import concurrent.futures
from colorama import Fore, Style

class SubdomainEnumerator:
    """Multi-source subdomain discovery"""
    
    def __init__(self, domain, wordlist_path=None):
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.discovered = set()
        
    def enumerate(self):
        """Use multiple methods to find subdomains"""
        print(f"{Fore.BLUE}[*] Enumerating subdomains for {self.domain}...{Style.RESET_ALL}")
        
        # Method 1: Certificate Transparency logs (crt.sh)
        print(f"  {Fore.CYAN}[1/4] Querying crt.sh...{Style.RESET_ALL}")
        crtsh_subs = self._query_crtsh()
        print(f"      Found: {len(crtsh_subs)} subdomains")
        self.discovered.update(crtsh_subs)
        
        # Method 2: AlienVault OTX (free, no API key)
        print(f"  {Fore.CYAN}[2/4] Querying AlienVault OTX...{Style.RESET_ALL}")
        otx_subs = self._query_alienvault()
        print(f"      Found: {len(otx_subs)} subdomains")
        self.discovered.update(otx_subs)
        
        # Method 3: URLScan.io
        print(f"  {Fore.CYAN}[3/4] Querying URLScan.io...{Style.RESET_ALL}")
        urlscan_subs = self._query_urlscan()
        print(f"      Found: {len(urlscan_subs)} subdomains")
        self.discovered.update(otx_subs)
        
        # Method 4: DNS brute-force (if wordlist provided)
        if self.wordlist_path:
            print(f"  {Fore.CYAN}[4/4] DNS brute-force...{Style.RESET_ALL}")
            brute_subs = self._brute_force()
            print(f"      Found: {len(brute_subs)} subdomains")
            self.discovered.update(brute_subs)
        
        # Resolve all discovered subdomains
        results = []
        for subdomain in list(self.discovered)[:50]:  # Limit to 50 for speed
            ips = self._resolve(subdomain)
            if ips:
                results.append({
                    'subdomain': subdomain,
                    'ips': ips
                })
                print(f"  {Fore.GREEN}[FOUND] {subdomain} → {', '.join(ips)}{Style.RESET_ALL}")
        
        print(f"  {Fore.GREEN}[+] Total unique subdomains: {len(results)}{Style.RESET_ALL}")
        return results
    
    def _query_crtsh(self):
        """Query Certificate Transparency logs"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30, headers={'User-Agent': 'Mozilla/5.0'})
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if '\n' in name:
                        for n in name.split('\n'):
                            if self.domain in n and '*' not in n:
                                subdomains.add(n.strip().lower())
                    elif self.domain in name and '*' not in name:
                        subdomains.add(name.strip().lower())
        except Exception as e:
            print(f"      {Fore.YELLOW}[!] crt.sh error: {e}{Style.RESET_ALL}")
        
        return subdomains
    
    def _query_alienvault(self):
        """Query AlienVault OTX passive DNS"""
        subdomains = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = requests.get(url, timeout=30, headers={'User-Agent': 'Mozilla/5.0'})
            
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '')
                    if self.domain in hostname and '*' not in hostname:
                        subdomains.add(hostname.lower())
        except Exception as e:
            print(f"      {Fore.YELLOW}[!] OTX error: {e}{Style.RESET_ALL}")
        
        return subdomains
    
    def _query_urlscan(self):
        """Query URLScan.io API"""
        subdomains = set()
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=100"
            response = requests.get(url, timeout=30, headers={'User-Agent': 'Mozilla/5.0'})
            
            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', []):
                    task_url = result.get('task', {}).get('url', '')
                    if task_url and self.domain in task_url:
                        # Extract domain from URL
                        from urllib.parse import urlparse
                        parsed = urlparse(task_url)
                        hostname = parsed.netloc.split(':')[0]
                        if self.domain in hostname:
                            subdomains.add(hostname.lower())
        except Exception as e:
            print(f"      {Fore.YELLOW}[!] URLScan error: {e}{Style.RESET_ALL}")
        
        return subdomains
    
    def _brute_force(self):
        """DNS brute-force with common subdomains"""
        subdomains = set()
        
        # Small built-in wordlist (most common)
        common_subs = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
            'smtp', 'secure', 'vpn', 'm', 'shop', 'ftp', 'api', 'dev', 'test',
            'portal', 'admin', 'app', 'stage', 'staging', 'prod', 'cdn', 'cloud',
            'support', 'status', 'login', 'auth', 'dashboard', 'monitor'
        ]
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        for sub in common_subs:
            try:
                fqdn = f"{sub}.{self.domain}"
                answers = resolver.resolve(fqdn, 'A')
                if answers:
                    subdomains.add(fqdn)
            except:
                pass
        
        return subdomains
    
    def _resolve(self, subdomain):
        """Resolve subdomain to IP addresses"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            answers = resolver.resolve(subdomain, 'A')
            return [str(r) for r in answers]
        except:
            return []
