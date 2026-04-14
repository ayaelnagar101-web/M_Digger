"""
Advanced Directory Fuzzer with Smart 404 Detection & WAF Evasion
"""
import requests
import concurrent.futures
import time
import random
from urllib.parse import urljoin
from colorama import Fore, Style

class DirectoryFuzzer:
    """Intelligent directory/file discovery with soft 404 detection"""
    
    def __init__(self, target, wordlist_path, extensions=None, threads=20):
        self.target = target if target.startswith(('http://', 'https://')) else f'https://{target}'
        self.wordlist_path = wordlist_path
        self.extensions = extensions or ['', '.php', '.html', '.txt', '.bak', '.old', '.zip']
        self.threads = threads
        self.stealth_mode = False
        self.stealth_requester = None
        
        # Soft 404 detection
        self.baseline_404_size = None
        self.baseline_404_content = None
        self.soft_404_threshold = 0.95  # 95% similarity threshold
        
        # Results storage
        self.discovered = []
        
    def set_stealth_mode(self, stealth_requester):
        """Enable stealth mode with custom requester"""
        self.stealth_mode = True
        self.stealth_requester = stealth_requester
    
    def fuzz(self):
        """Perform directory fuzzing"""
        print(f"{Fore.BLUE}[*] Fuzzing directories on {self.target}...{Style.RESET_ALL}")
        
        # Load wordlist
        try:
            with open(self.wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            print(f"  Loaded {len(words)} words from wordlist")
        except FileNotFoundError:
            print(f"  {Fore.RED}[!] Wordlist not found: {self.wordlist_path}{Style.RESET_ALL}")
            return []
        
        # Establish 404 baseline
        self._establish_baseline()
        
        # Generate all paths to test
        paths_to_test = []
        for word in words:
            for ext in self.extensions:
                paths_to_test.append(f"{word}{ext}")
        
        print(f"  Testing {len(paths_to_test)} paths with {self.threads} threads...")
        
        # Threaded scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._test_path, path): path 
                for path in paths_to_test
            }
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.discovered.append(result)
                        self._display_finding(result)
                except Exception as e:
                    pass
        
        print(f"  {Fore.GREEN}[+] Directory fuzzing complete: {len(self.discovered)} paths found{Style.RESET_ALL}")
        return self.discovered
    
    def _establish_baseline(self):
        """Learn what a 404 looks like on this server"""
        print(f"  {Fore.CYAN}[*] Establishing 404 baseline...{Style.RESET_ALL}")
        
        # Generate random non-existent path
        random_path = f"/nonexistent_{random.randint(10000, 99999)}.html"
        test_url = urljoin(self.target, random_path)
        
        try:
            if self.stealth_mode and self.stealth_requester:
                response = self.stealth_requester.get(test_url)
            else:
                response = requests.get(test_url, timeout=10, verify=False)
            
            if response:
                self.baseline_404_size = len(response.content)
                self.baseline_404_content = response.text[:1000]  # First 1000 chars
                print(f"  Baseline 404 size: {self.baseline_404_size} bytes")
        except:
            print(f"  {Fore.YELLOW}[!] Could not establish baseline{Style.RESET_ALL}")
    
    def _test_path(self, path):
        """Test individual path"""
        url = urljoin(self.target, path)
        
        try:
            # Add delay for stealth
            if self.stealth_mode:
                time.sleep(random.uniform(0.5, 1.5))
                response = self.stealth_requester.get(url)
            else:
                response = requests.get(url, timeout=10, verify=False, allow_redirects=False)
            
            if not response:
                return None
            
            status = response.status_code
            
            # Skip obvious 404s
            if status == 404:
                return None
            
            # Check for soft 404
            if self._is_soft_404(response):
                return None
            
            # Valid finding
            result = {
                'url': url,
                'path': path,
                'status': status,
                'size': len(response.content),
                'redirect': response.headers.get('Location') if status in [301, 302] else None,
                'server': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown')
            }
            
            # Extract page title for HTML
            if 'text/html' in result['content_type']:
                try:
                    import re
                    title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                    if title_match:
                        result['title'] = title_match.group(1)[:100]
                except:
                    pass
            
            return result
            
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            return None
        except Exception:
            return None
    
    def _is_soft_404(self, response):
        """Detect soft 404 responses (WAF/custom error pages)"""
        if response.status_code == 200:
            # Check content similarity to known 404
            if self.baseline_404_size and self.baseline_404_content:
                size_diff = abs(len(response.content) - self.baseline_404_size)
                size_similar = size_diff < 100  # Within 100 bytes
                
                # Check content keywords
                content_lower = response.text[:1000].lower()
                error_keywords = ['not found', '404', 'page not found', "doesn't exist", 'cannot be found']
                has_error_keyword = any(keyword in content_lower for keyword in error_keywords)
                
                return size_similar or has_error_keyword
        
        return False
    
    def _display_finding(self, result):
        """Display discovered path"""
        status_color = Fore.GREEN if result['status'] == 200 else Fore.YELLOW
        status_symbol = "✓" if result['status'] == 200 else "→"
        
        print(f"  {status_color}[{result['status']}] {status_symbol} {result['path']}{Style.RESET_ALL}")
        
        if result.get('redirect'):
            print(f"      {Fore.CYAN}→ Redirects to: {result['redirect']}{Style.RESET_ALL}")
        
        if result.get('title'):
            print(f"      {Fore.BLUE}Title: {result['title']}{Style.RESET_ALL}")
