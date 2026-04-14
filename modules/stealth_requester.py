"""
Stealth HTTP Requester with WAF Evasion & Dynamic Headers
"""
import requests
import random
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse
from colorama import Fore, Style
import sys
sys.path.append('.')
from config import Config

class RateLimiter:
    """Token bucket rate limiter for API compliance"""
    
    def __init__(self, requests_per_minute):
        self.rate = requests_per_minute
        self.tokens = requests_per_minute
        self.last_refill = datetime.now()
        self.min_interval = 60.0 / requests_per_minute
    
    def acquire(self):
        """Wait if necessary to respect rate limit"""
        now = datetime.now()
        time_passed = (now - self.last_refill).total_seconds()
        self.tokens = min(self.rate, self.tokens + time_passed * (self.rate / 60.0))
        self.last_refill = now
        
        if self.tokens < 1:
            sleep_time = self.min_interval
            time.sleep(sleep_time)
            self.tokens = 1
        else:
            self.tokens -= 1

class WAFDetector:
    """Detect WAF presence before active scanning"""
    
    @staticmethod
    def detect(target_url):
        """Check response headers and content for WAF signatures"""
        print(f"{Fore.CYAN}[*] Detecting WAF presence...{Style.RESET_ALL}")
        
        detected_wafs = []
        
        try:
            # Send probe request
            response = requests.get(
                target_url,
                timeout=10,
                allow_redirects=True,
                verify=False,
                headers={'User-Agent': random.choice(Config.USER_AGENTS)}
            )
            
            # Check headers
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            for waf_name, signatures in Config.WAF_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in str(headers_lower):
                        detected_wafs.append(waf_name)
                        break
            
            # Check for specific WAF behaviors
            if response.status_code == 403:
                if 'request blocked' in response.text.lower():
                    detected_wafs.append('Generic WAF')
            
            # Send malicious probe to trigger WAF
            malicious_url = f"{target_url}?id=1' OR '1'='1"
            mal_response = requests.get(malicious_url, timeout=10, verify=False)
            
            if mal_response.status_code == 403 or mal_response.status_code == 406:
                if 'mod_security' in mal_response.text.lower():
                    detected_wafs.append('ModSecurity')
            
            if detected_wafs:
                print(f"  {Fore.YELLOW}[!] WAF Detected: {', '.join(set(detected_wafs))}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}[+] No WAF detected{Style.RESET_ALL}")
            
            return list(set(detected_wafs))
            
        except Exception as e:
            print(f"  {Fore.RED}[!] WAF detection failed: {e}{Style.RESET_ALL}")
            return []

class StealthRequester:
    """Main stealth HTTP client with rotation and delays"""
    
    def __init__(self, base_delay=1.0, jitter=0.5):
        self.session = requests.Session()
        self.base_delay = base_delay
        self.jitter = jitter
        self.waf_detected = []
        self.request_count = 0
        
        # Configure session
        self.session.verify = False
        self.session.max_redirects = 3
        
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def _generate_headers(self, referer=None):
        """Generate realistic browser headers"""
        user_agent = random.choice(Config.USER_AGENTS)
        
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'en;q=0.7']),
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }
        
        if referer:
            headers['Referer'] = referer
        
        return headers
    
    def _random_delay(self):
        """Add randomized delay between requests"""
        delay = self.base_delay + random.uniform(0, self.jitter)
        time.sleep(delay)
    
    def get(self, url, **kwargs):
        """Stealth GET request"""
        self.request_count += 1
        
        # Add delay every few requests
        if self.request_count % 5 == 0:
            self._random_delay()
        
        # Generate headers
        headers = self._generate_headers(kwargs.get('headers', {}).get('Referer'))
        
        # Merge with custom headers
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        
        kwargs['headers'] = headers
        kwargs['timeout'] = kwargs.get('timeout', Config.REQUEST_TIMEOUT)
        
        try:
            response = self.session.get(url, **kwargs)
            return response
        except Exception as e:
            print(f"  {Fore.RED}[!] Request failed: {e}{Style.RESET_ALL}")
            return None
    
    def post(self, url, **kwargs):
        """Stealth POST request"""
        self._random_delay()
        
        headers = self._generate_headers()
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        
        kwargs['headers'] = headers
        kwargs['timeout'] = kwargs.get('timeout', Config.REQUEST_TIMEOUT)
        
        return self.session.post(url, **kwargs)
    
    def detect_waf(self, url):
        """Run WAF detection"""
        self.waf_detected = WAFDetector.detect(url)
        return self.waf_detected
