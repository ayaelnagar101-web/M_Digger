"""
Multi-Source API Manager with Rate Limiting
"""
import time
import json
from datetime import datetime, timedelta
from colorama import Fore, Style
import sys
sys.path.append('.')
from config import Config
from modules.stealth_requester import RateLimiter, StealthRequester

class APIManager:
    """Centralized API handling with rate limit compliance"""
    
    def __init__(self):
        self.stealth = StealthRequester()
        self.rate_limiters = {}
        self._init_rate_limiters()
        self.results = {
            'shodan': {},
            'virustotal': {},
            'censys': {},
            'hunter': {},
            'securitytrails': {}
        }
    
    def _init_rate_limiters(self):
        """Initialize rate limiters for each API"""
        for api, limit in Config.RATE_LIMITS.items():
            self.rate_limiters[api] = RateLimiter(limit)
    
    def _check_rate_limit(self, api_name):
        """Enforce rate limit before API call"""
        if api_name in self.rate_limiters:
            self.rate_limiters[api_name].acquire()
    
    def query_shodan(self, ip_address):
        """Query Shodan for IP intelligence"""
        if not Config.SHODAN_API_KEY:
            print(f"  {Fore.YELLOW}[!] Shodan API key not configured{Style.RESET_ALL}")
            return {}
        
        self._check_rate_limit('shodan')
        
        try:
            import shodan
            api = shodan.Shodan(Config.SHODAN_API_KEY)
            
            print(f"{Fore.BLUE}[*] Querying Shodan for {ip_address}...{Style.RESET_ALL}")
            
            try:
                host = api.host(ip_address)
                
                result = {
                    'ip': ip_address,
                    'ports': host.get('ports', []),
                    'vulns': host.get('vulns', []),
                    'hostnames': host.get('hostnames', []),
                    'os': host.get('os', 'Unknown'),
                    'org': host.get('org', 'Unknown'),
                    'isp': host.get('isp', 'Unknown'),
                    'country': host.get('country_name', 'Unknown'),
                    'data': []
                }
                
                # Process service data
                for item in host.get('data', []):
                    service = {
                        'port': item.get('port'),
                        'transport': item.get('transport', 'tcp'),
                        'product': item.get('product', 'Unknown'),
                        'version': item.get('version', ''),
                        'banner': item.get('data', '')[:200]
                    }
                    
                    # Extract CVEs if present
                    if 'vulns' in item:
                        service['cves'] = item['vulns']
                    
                    result['data'].append(service)
                
                print(f"  {Fore.GREEN}[+] Shodan: {len(result['ports'])} ports, {len(result['vulns'])} CVEs{Style.RESET_ALL}")
                
                self.results['shodan'] = result
                return result
                
            except shodan.APIError as e:
                if 'No information available' in str(e):
                    print(f"  {Fore.YELLOW}[-] Shodan: No data for this IP{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.RED}[!] Shodan API error: {e}{Style.RESET_ALL}")
                return {}
                
        except ImportError:
            print(f"  {Fore.RED}[!] Shodan library not installed{Style.RESET_ALL}")
            return {}
    
    def query_virustotal(self, domain):
        """Query VirusTotal for domain/subdomain intelligence"""
        if not Config.VIRUSTOTAL_API_KEY:
            print(f"  {Fore.YELLOW}[!] VirusTotal API key not configured{Style.RESET_ALL}")
            return {}
        
        self._check_rate_limit('virustotal')
        
        try:
            import vt
            client = vt.Client(Config.VIRUSTOTAL_API_KEY)
            
            print(f"{Fore.BLUE}[*] Querying VirusTotal for {domain}...{Style.RESET_ALL}")
            
            result = {
                'domain': domain,
                'subdomains': [],
                'resolutions': [],
                'reputation': 0,
                'categories': {}
            }
            
            try:
                # Get domain report
                domain_obj = client.get_object(f'/domains/{domain}')
                
                # Get subdomains
                try:
                    subdomains = client.get(f'/domains/{domain}/subdomains')
                    for sub in subdomains:
                        if hasattr(sub, 'id'):
                            result['subdomains'].append(sub.id)
                except:
                    pass
                
                # Get DNS resolutions
                try:
                    resolutions = client.get(f'/domains/{domain}/resolutions')
                    for res in resolutions:
                        if hasattr(res, 'ip_address'):
                            result['resolutions'].append({
                                'ip': res.ip_address,
                                'date': res.date.isoformat() if hasattr(res, 'date') else None
                            })
                except:
                    pass
                
                # Get reputation
                if hasattr(domain_obj, 'reputation'):
                    result['reputation'] = domain_obj.reputation
                
                # Get categories
                if hasattr(domain_obj, 'categories'):
                    result['categories'] = domain_obj.categories
                
                print(f"  {Fore.GREEN}[+] VirusTotal: {len(result['subdomains'])} subdomains{Style.RESET_ALL}")
                
                client.close()
                self.results['virustotal'] = result
                return result
                
            except vt.error.APIError as e:
                if 'NotFoundError' in str(e):
                    print(f"  {Fore.YELLOW}[-] VirusTotal: No data for this domain{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.RED}[!] VirusTotal API error: {e}{Style.RESET_ALL}")
                return {}
                
        except ImportError:
            print(f"  {Fore.RED}[!] vt-py library not installed{Style.RESET_ALL}")
            return {}
        except Exception as e:
            print(f"  {Fore.RED}[!] VirusTotal error: {e}{Style.RESET_ALL}")
            return {}
    
    def query_censys(self, domain):
        """Query Censys for SSL certificate data"""
        if not Config.CENSYS_API_ID or not Config.CENSYS_API_SECRET:
            print(f"  {Fore.YELLOW}[!] Censys API credentials not configured{Style.RESET_ALL}")
            return {}
        
        self._check_rate_limit('censys')
        
        try:
            from censys.search import CensysCertificates
            
            print(f"{Fore.BLUE}[*] Querying Censys for {domain} certificates...{Style.RESET_ALL}")
            
            c = CensysCertificates(
                api_id=Config.CENSYS_API_ID,
                api_secret=Config.CENSYS_API_SECRET
            )
            
            result = {
                'domain': domain,
                'certificates': [],
                'associated_hosts': []
            }
            
            try:
                # Search for certificates
                query = c.search(f'parsed.names: {domain}', per_page=10)
                
                for cert in query:
                    cert_data = {
                        'fingerprint': cert.get('parsed.fingerprint_sha256', '')[:16],
                        'issuer': cert.get('parsed.issuer_dn', ''),
                        'valid_from': cert.get('parsed.validity.start', ''),
                        'valid_until': cert.get('parsed.validity.end', ''),
                        'sans': cert.get('parsed.names', [])
                    }
                    result['certificates'].append(cert_data)
                    
                    # Collect associated hosts
                    for san in cert_data['sans']:
                        if san not in result['associated_hosts']:
                            result['associated_hosts'].append(san)
                
                print(f"  {Fore.GREEN}[+] Censys: {len(result['certificates'])} certs, {len(result['associated_hosts'])} hosts{Style.RESET_ALL}")
                
                self.results['censys'] = result
                return result
                
            except Exception as e:
                print(f"  {Fore.RED}[!] Censys search error: {e}{Style.RESET_ALL}")
                return {}
                
        except ImportError:
            print(f"  {Fore.RED}[!] Censys library not installed{Style.RESET_ALL}")
            return {}
    
    def query_hunter(self, domain):
        """Query Hunter.io for email discovery"""
        if not Config.HUNTER_API_KEY:
            print(f"  {Fore.YELLOW}[!] Hunter.io API key not configured{Style.RESET_ALL}")
            return {}
        
        self._check_rate_limit('hunter')
        
        print(f"{Fore.BLUE}[*] Querying Hunter.io for {domain} emails...{Style.RESET_ALL}")
        
        result = {
            'domain': domain,
            'emails': [],
            'pattern': None,
            'organization': None
        }
        
        try:
            url = f"https://api.hunter.io/v2/domain-search"
            params = {
                'domain': domain,
                'api_key': Config.HUNTER_API_KEY
            }
            
            response = self.stealth.get(url, params=params)
            
            if response and response.status_code == 200:
                data = response.json()
                
                if 'data' in data:
                    result['pattern'] = data['data'].get('pattern')
                    result['organization'] = data['data'].get('organization')
                    
                    for email in data['data'].get('emails', []):
                        email_info = {
                            'email': email.get('value'),
                            'type': email.get('type'),
                            'confidence': email.get('confidence'),
                            'sources': email.get('sources', [])[:3]
                        }
                        result['emails'].append(email_info)
                    
                    print(f"  {Fore.GREEN}[+] Hunter.io: {len(result['emails'])} emails found{Style.RESET_ALL}")
                    
                    self.results['hunter'] = result
                    return result
            else:
                print(f"  {Fore.YELLOW}[-] Hunter.io: No emails found{Style.RESET_ALL}")
                return {}
                
        except Exception as e:
            print(f"  {Fore.RED}[!] Hunter.io error: {e}{Style.RESET_ALL}")
            return {}
    
    def aggregate_passive_findings(self):
        """Combine all passive intelligence"""
        aggregated = {
            'subdomains': set(),
            'ips': set(),
            'ports': {},
            'emails': [],
            'certificates': []
        }
        
        # From VirusTotal
        if self.results['virustotal']:
            aggregated['subdomains'].update(self.results['virustotal'].get('subdomains', []))
            for res in self.results['virustotal'].get('resolutions', []):
                if res.get('ip'):
                    aggregated['ips'].add(res['ip'])
        
        # From Censys
        if self.results['censys']:
            aggregated['certificates'].extend(self.results['censys'].get('certificates', []))
            for host in self.results['censys'].get('associated_hosts', []):
                if host != self.results['censys']['domain']:
                    aggregated['subdomains'].add(host)
        
        # From Hunter.io
        if self.results['hunter']:
            aggregated['emails'] = self.results['hunter'].get('emails', [])
        
        # From Shodan
        if self.results['shodan']:
            for hostname in self.results['shodan'].get('hostnames', []):
                aggregated['subdomains'].add(hostname)
            
            for service in self.results['shodan'].get('data', []):
                port = service.get('port')
                if port:
                    ip = self.results['shodan']['ip']
                    if ip not in aggregated['ports']:
                        aggregated['ports'][ip] = []
                    aggregated['ports'][ip].append({
                        'port': port,
                        'service': service.get('product', 'Unknown'),
                        'version': service.get('version', ''),
                        'cves': service.get('cves', [])
                    })
        
        # Convert sets to lists
        aggregated['subdomains'] = list(aggregated['subdomains'])
        aggregated['ips'] = list(aggregated['ips'])
        
        return aggregated
