"""
Professional WAF Detection using wafw00f engine
"""
import asyncio
import sys
from colorama import Fore, Style
from wafw00f.main import WAFW00F
from wafw00f.lib.evillib import waftoolsengine

class WAFDetector:
    """WAF detection using wafw00f's behavioral analysis engine"""
    
    def __init__(self, target):
        self.target = target
        self.detected_wafs = []
        self.confidence = {}
        
    def detect(self):
        """Run comprehensive WAF detection"""
        print(f"{Fore.CYAN}[*] Running WAF detection with wafw00f engine...{Style.RESET_ALL}")
        
        # Ensure URL has scheme
        url = self.target
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        try:
            # Initialize wafw00f engine
            attacker = waftoolsengine(url)
            
            # Step 1: Send normal request to establish baseline
            print(f"  {Fore.BLUE}[1/3] Establishing baseline...{Style.RESET_ALL}")
            attacker.normalRequest()
            
            if attacker.r is None:
                print(f"  {Fore.RED}[!] Cannot reach target. Check connectivity.{Style.RESET_ALL}")
                return []
            
            # Step 2: Send attack payloads to trigger WAF
            print(f"  {Fore.BLUE}[2/3] Sending probe payloads...{Style.RESET_ALL}")
            
            # Test multiple attack vectors
            attack_results = {}
            
            # XSS Probe
            attacker.xssAttack()
            attack_results['xss'] = self._analyze_response(attacker)
            
            # SQLi Probe  
            attacker.sqliAttack()
            attack_results['sqli'] = self._analyze_response(attacker)
            
            # LFI Probe
            attacker.lfiAttack()
            attack_results['lfi'] = self._analyze_response(attacker)
            
            # Combined probe (most effective)
            attacker.centralAttack()
            attack_results['combined'] = self._analyze_response(attacker)
            
            # Step 3: Fingerprint WAF based on behavioral differences
            print(f"  {Fore.BLUE}[3/3] Fingerprinting WAF...{Style.RESET_ALL}")
            
            # Check for known WAF patterns
            self._fingerprint_waf(attacker)
            
            # Display results
            if self.detected_wafs:
                print(f"\n  {Fore.YELLOW}[!] WAF Detected: {', '.join(self.detected_wafs)}{Style.RESET_ALL}")
                
                # Show evidence
                for waf in self.detected_wafs:
                    if waf in self.confidence:
                        print(f"      - {waf}: {self.confidence[waf]}")
            else:
                print(f"  {Fore.GREEN}[+] No WAF detected (or WAF is transparent){Style.RESET_ALL}")
            
            return self.detected_wafs
            
        except Exception as e:
            print(f"  {Fore.RED}[!] WAF detection error: {e}{Style.RESET_ALL}")
            return []
    
    def _analyze_response(self, attacker):
        """Analyze attack response for WAF indicators"""
        indicators = {
            'status': attacker.r.status_code if attacker.r else None,
            'blocked': False,
            'headers': {}
        }
        
        if attacker.r:
            # Check for blocking
            if attacker.r.status_code in [403, 406, 429, 503]:
                indicators['blocked'] = True
            
            # Extract security headers
            security_headers = [
                'X-CDN', 'X-Cache', 'X-Amz-Cf-Id', 'CF-Ray',
                'X-Sucuri-ID', 'X-Cloud-Trace-Context',
                'Server', 'X-Powered-By', 'X-AspNet-Version'
            ]
            
            for header in security_headers:
                if header in attacker.r.headers:
                    indicators['headers'][header] = attacker.r.headers[header]
        
        return indicators
    
    def _fingerprint_waf(self, attacker):
        """Identify specific WAF based on behavioral signatures"""
        
        # Cloudflare detection
        if attacker.r:
            headers = attacker.r.headers
            
            # Cloudflare signatures
            if 'CF-Ray' in headers or 'cf-ray' in headers:
                self.detected_wafs.append('Cloudflare')
                self.confidence['Cloudflare'] = 'High (CF-Ray header present)'
            
            elif headers.get('Server') == 'cloudflare':
                self.detected_wafs.append('Cloudflare')
                self.confidence['Cloudflare'] = 'Medium (Server header)'
            
            # AWS CloudFront / WAF
            if 'X-Amz-Cf-Id' in headers or 'X-Amz-Cf-Pop' in headers:
                self.detected_wafs.append('AWS CloudFront')
                self.confidence['AWS CloudFront'] = 'High (CloudFront headers)'
            
            elif headers.get('Server') == 'CloudFront':
                self.detected_wafs.append('AWS CloudFront')
                self.confidence['AWS CloudFront'] = 'Medium'
            
            # Google Cloud Armor
            if 'X-Cloud-Trace-Context' in headers:
                self.detected_wafs.append('Google Cloud Armor')
                self.confidence['Google Cloud Armor'] = 'High'
            
            # Sucuri
            if 'X-Sucuri-ID' in headers or 'Sucuri' in str(headers):
                self.detected_wafs.append('Sucuri')
                self.confidence['Sucuri'] = 'High'
            
            # Imperva/Incapsula
            if 'X-Iinfo' in headers or 'X-CDN' in headers:
                if 'Incapsula' in str(headers.get('X-CDN', '')):
                    self.detected_wafs.append('Imperva Incapsula')
                    self.confidence['Imperva Incapsula'] = 'High'
            
            # Akamai
            if 'X-Akamai-Transformed' in headers or 'Akamai' in headers.get('Server', ''):
                self.detected_wafs.append('Akamai')
                self.confidence['Akamai'] = 'High'
            
            # ModSecurity (behavioral detection)
            if self._detect_modsecurity_behavior(attacker):
                self.detected_wafs.append('ModSecurity')
                self.confidence['ModSecurity'] = 'Behavioral analysis'
            
            # Generic WAF (based on blocking behavior)
            if not self.detected_wafs and self._detect_generic_waf(attacker):
                self.detected_wafs.append('Generic WAF/IPS')
                self.confidence['Generic WAF/IPS'] = 'Request blocked with 403/406'
    
    def _detect_modsecurity_behavior(self, attacker):
        """Detect ModSecurity based on response patterns"""
        if not attacker.r:
            return False
        
        # ModSecurity typically returns 403 with specific body patterns
        if attacker.r.status_code == 403:
            content = attacker.r.text.lower()
            modsec_patterns = [
                'mod_security',
                'modsecurity',
                'this error was generated by mod_security',
                'the request was rejected',
                'not acceptable'
            ]
            
            for pattern in modsec_patterns:
                if pattern in content:
                    return True
        
        return False
    
    def _detect_generic_waf(self, attacker):
        """Detect generic WAF based on blocking behavior"""
        if not attacker.r:
            return False
        
        # Check if attack request was blocked while normal request passed
        if attacker.r.status_code in [403, 406, 429]:
            return True
        
        # Check for security-related response headers
        security_headers = ['X-WAF', 'X-Firewall', 'X-Proxy', 'X-Security']
        for header in security_headers:
            if any(h.lower().startswith(header.lower()) for h in attacker.r.headers):
                return True
        
        return False
    
    def get_evasion_strategy(self):
        """Return recommended evasion strategies based on detected WAF"""
        strategies = {
            'Cloudflare': [
                'Use rotating User-Agents from real browsers',
                'Implement longer delays between requests (2-5 seconds)',
                'Respect robots.txt patterns',
                'Use TLS fingerprint randomization'
            ],
            'AWS CloudFront': [
                'Distribute requests across different IPs',
                'Use realistic Accept-Language headers',
                'Avoid sequential port scanning'
            ],
            'Google Cloud Armor': [
                'Use Google bot User-Agents cautiously',
                'Implement exponential backoff on 429 responses',
                'Avoid SQLi patterns in URL parameters'
            ],
            'ModSecurity': [
                'URL-encode special characters',
                'Use POST instead of GET for fuzzing',
                'Avoid common SQLi/XSS keywords in headers'
            ],
            'Imperva Incapsula': [
                'Maintain cookies between requests',
                'Use JavaScript-capable client for certain endpoints',
                'Respect rate limits strictly'
            ],
            'Generic WAF/IPS': [
                'Slow down scanning speed significantly',
                'Randomize request order',
                'Use HTTP/1.0 occasionally'
            ]
        }
        
        detected = self.detected_wafs[0] if self.detected_wafs else None
        return strategies.get(detected, ['No specific evasion needed'])
