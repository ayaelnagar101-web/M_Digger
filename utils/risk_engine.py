"""
Risk Assessment Engine with VAPT Standards
"""
from colorama import Fore, Style

class RiskEngine:
    """Calculate risk ratings based on findings"""
    
    RISK_LEVELS = {
        'CRITICAL': {'color': Fore.RED, 'score': 5},
        'HIGH': {'color': Fore.LIGHTRED_EX, 'score': 4},
        'MEDIUM': {'color': Fore.YELLOW, 'score': 3},
        'LOW': {'color': Fore.GREEN, 'score': 2},
        'INFO': {'color': Fore.BLUE, 'score': 1}
    }
    
    def __init__(self):
        self.critical_cves = ['CVE-2021-44228', 'CVE-2022-22965', 'CVE-2021-34527']
    
    def assess(self, findings):
        """Generate risk assessment"""
        assessment = {
            'findings': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'overall_risk': 'LOW'
        }
        
        # Check passive findings
        if 'passive' in findings:
            # Shodan CVEs
            if 'shodan' in findings['passive']:
                shodan = findings['passive']['shodan']
                for service in shodan.get('data', []):
                    for cve in service.get('cves', []):
                        if cve in self.critical_cves:
                            risk = 'CRITICAL'
                        else:
                            risk = 'HIGH'
                        
                        assessment['findings'].append({
                            'source': 'Shodan',
                            'type': 'CVE',
                            'detail': f"{cve} on port {service['port']}",
                            'risk': risk
                        })
                        assessment['summary'][risk.lower()] += 1
        
        # Check active findings
        if 'active' in findings:
            # Open dangerous ports
            for port_info in findings['active'].get('ports', []):
                if port_info['port'] in [23, 21]:  # Telnet, FTP
                    risk = 'HIGH'
                    assessment['findings'].append({
                        'source': 'Port Scanner',
                        'type': 'Dangerous Service',
                        'detail': f"Port {port_info['port']} open",
                        'risk': risk
                    })
                    assessment['summary'][risk.lower()] += 1
        
        # Determine overall risk
        if assessment['summary']['critical'] > 0:
            assessment['overall_risk'] = 'CRITICAL'
        elif assessment['summary']['high'] > 0:
            assessment['overall_risk'] = 'HIGH'
        elif assessment['summary']['medium'] > 0:
            assessment['overall_risk'] = 'MEDIUM'
        
        return assessment
