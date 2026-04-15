"""
Google Cloud Armor Detection - Behavioral Fingerprinting
"""
import requests
import time
from urllib.parse import urlparse
from colorama import Fore, Style

class WAFDetector:
    """Detect WAFs including Google Cloud Armor via behavioral analysis"""
    
    def __init__(self, target):
        self.target = target
        self.detected_wafs = []
        self.evidence = {}
        
        # Ensure URL has scheme
        if not self.target.startswith(('http://', 'https://')):
            self.target = f'https://{self.target}'
    
    def detect(self):
        """Run behavioral WAF detection"""
        print(f"{Fore.CYAN}[*] Running behavioral WAF detection...{Style.RESET_ALL}")
        
        # Test 1: Baseline request
        baseline = self._send_request('/')
        
        if not baseline:
            print(f"  {Fore.RED}[!] Cannot reach target{Style.RESET_ALL}")
            return []
        
        # Test 2: Check for Google Cloud Armor specifically
        print(f"  {Fore.BLUE}[1/3] Checking for Google Cloud Armor...{Style.RESET_ALL}")
        self._detect_google_cloud_armor(baseline)
        
        # Test 3: Generic WAF behavioral detection
        print(f"  {Fore.BLUE}[2/3] Testing with attack payloads...{Style.RESET_ALL}")
        self._detect_generic_waf()
        
        # Test 4: Response timing analysis
        print(f"  {Fore.BLUE}[3/3] Analyzing response patterns...{Style.RESET_ALL}")
        self._analyze_timing()
        
        # Display results
        if self.detected_wafs:
            print(f"\n  {Fore.YELLOW}[!] WAF Detected: {', '.join(self.detected_wafs)}{Style.RESET_ALL}")
            for waf, evidence in self.evidence.items():
                print(f"      - {waf}: {evidence}")
        else:
            print(f"  {Fore.GREEN}[+] No WAF detected (or transparent proxy){Style.RESET_ALL}")
        
        return self.detected_wafs
    
    def _send_request(self, path='/', params=None, headers=None):
        """Send HTTP request and return response data"""
        url = self.target.rstrip('/') + path
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*'
        }
        
        if headers:
            default_headers.update(headers)
        
        try:
            response = requests.get(
                url,
                params=params,
                headers=default_headers,
                timeout=10,
                allow_redirects=False,
                verify=False
            )
            
            return {
                'status': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:500],
                'time': response.elapsed.total_seconds()
            }
        except Exception as e:
            return None
    
    def _detect_google_cloud_armor(self, baseline):
        """Google Cloud Armor specific detection"""
        headers = baseline.get('headers', {})
        detected = False
        
        # PRIMARY INDICATOR: Via header with google
        via_header = headers.get('Via', '')
        if 'google' in via_header.lower():
            self.evidence['Google Cloud Armor'] = f"Via header: {via_header}"
            detected = True
            print(f"      {Fore.GREEN}[+] Found Google signature in Via header{Style.RESET_ALL}")
        
        # SECONDARY INDICATOR: Server header patterns
        server = headers.get('Server', '').lower()
        if 'gws' in server or 'gfe' in server:
            if 'Google Cloud Armor' not in self.evidence:
                self.evidence['Google Cloud Armor'] = f"Server header: {server}"
            detected = True
            print(f"      {Fore.GREEN}[+] Found Google frontend server{Style.RESET_ALL}")
        
        # TERTIARY INDICATOR: Specific error response patterns
        if baseline['status'] == 429:
            body = baseline.get('body', '').lower()
            if 'quota' in body or 'rate' in body:
                if 'Google Cloud Armor' not in self.evidence:
                    self.evidence['Google Cloud Armor'] = "Rate limiting behavior matches GCP"
                detected = True
                print(f"      {Fore.GREEN}[+] GCP-style rate limiting detected{Style.RESET_ALL}")
        
        if detected:
            self.detected_wafs.append('Google Cloud Armor')
    
    def _detect_generic_waf(self):
        """Detect WAF by sending attack payloads"""
        test_payloads = [
            ('/wp-admin', None, 'Path probe'),
            ('/', {'id': "1' OR '1'='1"}, 'SQLi probe'),
            ('/', {'q': '<script>alert(1)</script>'}, 'XSS probe'),
            ('/', {'file': '../../../etc/passwd'}, 'LFI probe'),
            ('/.env', None, 'Sensitive file probe'),
        ]
        
        baseline = self._send_request('/')
        baseline_status = baseline['status'] if baseline else 200
        
        for path, params, desc in test_payloads:
            time.sleep(0.5)  # Avoid rate limiting
            
            response = self._send_request(path, params)
            if not response:
                continue
            
            status = response['status']
            
            # Check for blocking behavior
            if status in [403, 406, 429, 503]:
                if baseline_status not in [403, 406, 429, 503]:
                    if 'Generic WAF' not in self.detected_wafs:
                        self.detected_wafs.append('Generic WAF')
                        self.evidence['Generic WAF'] = f"Blocked {desc} (HTTP {status})"
                    print(f"      {Fore.YELLOW}[!] {desc} blocked with {status}{Style.RESET_ALL}")
                    break
            
            # Check for Cloudflare
            headers = response.get('headers', {})
            if 'CF-Ray' in headers or 'cf-ray' in headers:
                if 'Cloudflare' not in self.detected_wafs:
                    self.detected_wafs.append('Cloudflare')
                    self.evidence['Cloudflare'] = 'CF-Ray header present'
                print(f"      {Fore.GREEN}[+] Cloudflare detected{Style.RESET_ALL}")
                break
            
            # Check for AWS WAF/CloudFront
            if 'X-Amz-Cf-Id' in headers:
                if 'AWS CloudFront' not in self.detected_wafs:
                    self.detected_wafs.append('AWS CloudFront')
                    self.evidence['AWS CloudFront'] = 'X-Amz-Cf-Id header present'
                print(f"      {Fore.GREEN}[+] AWS CloudFront detected{Style.RESET_ALL}")
                break
            
            # Check for ModSecurity in response body
            body = response.get('body', '').lower()
            if 'mod_security' in body or 'modsecurity' in body:
                if 'ModSecurity' not in self.detected_wafs:
                    self.detected_wafs.append('ModSecurity')
                    self.evidence['ModSecurity'] = 'ModSecurity signature in response'
                print(f"      {Fore.GREEN}[+] ModSecurity detected{Style.RESET_ALL}")
                break
    
    def _analyze_timing(self):
        """Analyze response timing for WAF indicators"""
        normal_times = []
        attack_times = []
        
        # Measure normal response times
        for _ in range(3):
            response = self._send_request('/')
            if response:
                normal_times.append(response['time'])
            time.sleep(0.2)
        
        # Measure attack response times
        attack_payloads = [
            ('/', {'id': "1' OR '1'='1"}),
            ('/', {'q': '<script>alert(1)</script>'}),
        ]
        
        for path, params in attack_payloads:
            response = self._send_request(path, params)
            if response:
                attack_times.append(response['time'])
            time.sleep(0.3)
        
        if normal_times and attack_times:
            avg_normal = sum(normal_times) / len(normal_times)
            avg_attack = sum(attack_times) / len(attack_times)
            
            # Significant delay indicates WAF inspection
            if avg_attack > avg_normal * 1.5:
                print(f"      {Fore.YELLOW}[!] Response delay detected: {avg_normal:.2f}s → {avg_attack:.2f}s{Style.RESET_ALL}")
                
                if not self.detected_wafs:
                    self.detected_wafs.append('WAF (Timing-based)')
                    self.evidence['WAF (Timing-based)'] = f"Attack requests {(avg_attack/avg_normal):.1f}x slower"
    
    def get_evasion_strategy(self):
        """Return evasion strategies based on detected WAF"""
        strategies = {
            'Google Cloud Armor': [
                'GCP Cloud Armor evasion:',
                '  - Use longer delays (3-7 seconds between requests)',
                '  - Rotate User-Agent with each request',
                '  - Avoid sequential scanning patterns',
                '  - Implement exponential backoff on 429 responses',
                '  - Consider using different source IPs (proxy rotation)',
                '  - Bypass tip: GCP Armor is vulnerable to parsing discrepancies',
                '    (Content-Type confusion attacks) [citation:7][citation:9]'
            ],
            'Cloudflare': [
                'Cloudflare evasion:',
                '  - Use browser-like TLS fingerprints',
                '  - Maintain cookies between requests',
                '  - Respect robots.txt patterns',
                '  - Distribute scans across multiple IPs'
            ],
            'AWS CloudFront': [
                'AWS WAF evasion:',
                '  - Avoid rapid sequential requests',
                '  - Use geographically distributed IPs',
                '  - Implement jitter in request timing'
            ],
            'ModSecurity': [
                'ModSecurity evasion:',
                '  - URL-encode special characters',
                '  - Use POST instead of GET for payloads',
                '  - Avoid common SQLi/XSS keywords'
            ],
            'Generic WAF': [
                'Generic WAF evasion:',
                '  - Slow down scanning speed',
                '  - Randomize request order',
                '  - Use legitimate-looking User-Agent headers',
                '  - Add realistic Accept-Language headers'
            ]
        }
        
        detected = self.detected_wafs[0] if self.detected_wafs else None
        
        # Partial match for Google Cloud Armor (handles variations)
        if detected:
            for key in strategies:
                if key.lower() in detected.lower():
                    return strategies[key]
        
        return strategies.get(detected, ['No specific evasion strategy needed'])


# Standalone test function
def test_waf_detection(target_url):
    """Test WAF detection on a single target"""
    detector = WAFDetector(target_url)
    result = detector.detect()
    
    if result:
        print(f"\n{Fore.YELLOW}Evasion Strategies:{Style.RESET_ALL}")
        for strategy in detector.get_evasion_strategy():
            print(f"  {strategy}")
    
    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        test_waf_detection(sys.argv[1])
    else:
        # Test on a known GCP-protected site
        print("Testing on a GCP site...")
        test_waf_detection("https://cloud.google.com")
