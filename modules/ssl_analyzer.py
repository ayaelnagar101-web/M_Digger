"""
SSL/TLS Certificate Analysis with SAN Extraction
"""
import ssl
import socket
import OpenSSL
from datetime import datetime
from colorama import Fore, Style
import sys
sys.path.append('.')
from config import Config

class SSLAnalyzer:
    """Deep SSL/TLS certificate analysis"""
    
    def __init__(self, domain, port=443):
        self.domain = domain
        self.port = port
        
    def analyze(self):
        """Extract all certificate information"""
        print(f"{Fore.BLUE}[*] Analyzing SSL certificate for {self.domain}:{self.port}...{Style.RESET_ALL}")
        
        result = {
            'domain': self.domain,
            'port': self.port,
            'certificates': [],
            'sans': set(),
            'issuers': set(),
            'vulnerabilities': [],
            'validation': {}
        }
        
        try:
            # Get certificate chain
            cert_chain = self._get_certificate_chain()
            
            for cert in cert_chain:
                cert_info = self._parse_certificate(cert)
                result['certificates'].append(cert_info)
                
                # Collect SANs
                if 'sans' in cert_info:
                    for san in cert_info['sans']:
                        result['sans'].add(san)
                
                # Collect issuers
                if 'issuer' in cert_info:
                    result['issuers'].add(cert_info['issuer'].get('organizationName', 'Unknown'))
            
            # Convert sets to lists
            result['sans'] = list(result['sans'])
            result['issuers'] = list(result['issuers'])
            
            # Check for vulnerabilities
            result['vulnerabilities'] = self._check_vulnerabilities(result['certificates'][0])
            
            # Validate certificate
            result['validation'] = self._validate_certificate(result['certificates'][0])
            
            # Display findings
            print(f"  {Fore.GREEN}[+] Certificate Chain: {len(result['certificates'])} certs{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}[+] Subject Alternative Names: {len(result['sans'])} found{Style.RESET_ALL}")
            
            # Show first 5 SANs
            for san in result['sans'][:5]:
                print(f"      - {san}")
            if len(result['sans']) > 5:
                print(f"      ... and {len(result['sans']) - 5} more")
            
            # Show vulnerabilities
            if result['vulnerabilities']:
                print(f"  {Fore.YELLOW}[!] Certificate Issues:{Style.RESET_ALL}")
                for vuln in result['vulnerabilities']:
                    print(f"      - {vuln}")
            
            # Show validation
            if result['validation'].get('expired'):
                print(f"  {Fore.RED}[!] Certificate EXPIRED{Style.RESET_ALL}")
            elif result['validation'].get('expires_soon'):
                print(f"  {Fore.YELLOW}[!] Certificate expires soon ({result['validation']['days_until_expiry']} days){Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}[+] Certificate valid for {result['validation']['days_until_expiry']} more days{Style.RESET_ALL}")
            
            return result
            
        except Exception as e:
            print(f"  {Fore.RED}[!] SSL analysis failed: {e}{Style.RESET_ALL}")
            result['error'] = str(e)
            return result
    
    def _get_certificate_chain(self):
        """Retrieve full certificate chain"""
        certs = []
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((self.domain, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    certs.append(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der))
                    
                    # Try to get chain
                    try:
                        chain = ssock.get_peer_cert_chain()
                        if chain:
                            for cert in chain:
                                certs.append(cert)
                    except:
                        pass
            
            return certs
            
        except Exception as e:
            print(f"    {Fore.RED}[!] Failed to retrieve certificate chain: {e}{Style.RESET_ALL}")
            return []
    
    def _parse_certificate(self, cert):
        """Parse OpenSSL certificate object"""
        cert_info = {
            'subject': {},
            'issuer': {},
            'serial_number': str(cert.get_serial_number()),
            'version': cert.get_version(),
            'not_before': None,
            'not_after': None,
            'signature_algorithm': cert.get_signature_algorithm().decode('utf-8') if cert.get_signature_algorithm() else None,
            'has_expired': cert.has_expired(),
            'sans': []
        }
        
        # Parse subject
        for key, value in cert.get_subject().get_components():
            key_name = key.decode('utf-8')
            value_str = value.decode('utf-8')
            cert_info['subject'][key_name] = value_str
        
        # Parse issuer
        for key, value in cert.get_issuer().get_components():
            key_name = key.decode('utf-8')
            value_str = value.decode('utf-8')
            cert_info['issuer'][key_name] = value_str
        
        # Parse dates
        if cert.get_notBefore():
            cert_info['not_before'] = datetime.strptime(
                cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'
            ).isoformat()
        
        if cert.get_notAfter():
            cert_info['not_after'] = datetime.strptime(
                cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'
            ).isoformat()
        
        # Extract SANs
        try:
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                if ext.get_short_name() == b'subjectAltName':
                    san_str = str(ext)
                    # Parse DNS entries
                    for line in san_str.split(','):
                        if 'DNS:' in line:
                            san = line.split('DNS:')[1].strip()
                            cert_info['sans'].append(san)
        except:
            pass
        
        return cert_info
    
    def _check_vulnerabilities(self, cert_info):
        """Check for common certificate issues"""
        vulnerabilities = []
        
        # Check signature algorithm
        if cert_info.get('signature_algorithm'):
            sig_alg = cert_info['signature_algorithm'].lower()
            if 'sha1' in sig_alg:
                vulnerabilities.append("Uses SHA-1 (deprecated and weak)")
            if 'md5' in sig_alg:
                vulnerabilities.append("Uses MD5 (cryptographically broken)")
        
        # Check key size (if we can extract it)
        # This would require additional parsing
        
        # Check expiration
        if cert_info.get('has_expired'):
            vulnerabilities.append("Certificate has EXPIRED")
        
        # Check wildcard
        if any(san.startswith('*.') for san in cert_info.get('sans', [])):
            vulnerabilities.append("Wildcard certificate in use (increased attack surface)")
        
        return vulnerabilities
    
    def _validate_certificate(self, cert_info):
        """Validate certificate health"""
        validation = {
            'valid': True,
            'expired': False,
            'expires_soon': False,
            'days_until_expiry': None
        }
        
        if cert_info.get('not_after'):
            try:
                expiry = datetime.fromisoformat(cert_info['not_after'])
                now = datetime.now()
                days_left = (expiry - now).days
                
                validation['days_until_expiry'] = days_left
                
                if days_left < 0:
                    validation['expired'] = True
                    validation['valid'] = False
                elif days_left < 30:
                    validation['expires_soon'] = True
            except:
                pass
        
        return validation
