"""
Correlation Engine - Verify findings across sources
"""

class CorrelationEngine:
    """Cross-reference findings for verification"""
    
    def verify_findings(self, findings):
        """Compare passive and active findings"""
        verified = []
        
        # Compare ports
        passive_ports = set()
        if 'passive' in findings and 'shodan' in findings['passive']:
            for service in findings['passive']['shodan'].get('data', []):
                passive_ports.add(service['port'])
        
        active_ports = set()
        if 'active' in findings and 'ports' in findings['active']:
            for port_info in findings['active']['ports']:
                if port_info['state'] == 'open':
                    active_ports.add(port_info['port'])
        
        # Find verified ports
        verified_ports = passive_ports & active_ports
        for port in verified_ports:
            verified.append({
                'type': 'port',
                'value': port,
                'confidence': 'HIGH',
                'sources': ['Shodan', 'Active Scan']
            })
        
        # Compare subdomains
        passive_subs = set()
        if 'passive' in findings:
            if 'virustotal' in findings['passive']:
                passive_subs.update(findings['passive']['virustotal'].get('subdomains', []))
            if 'ssl' in findings['passive']:
                passive_subs.update(findings['passive']['ssl'].get('sans', []))
        
        active_subs = set()
        if 'active' in findings and 'subdomains' in findings['active']:
            active_subs.update(findings['active']['subdomains'])
        
        verified_subs = passive_subs & active_subs
        for sub in list(verified_subs)[:10]:  # Limit to 10 for display
            verified.append({
                'type': 'subdomain',
                'value': sub,
                'confidence': 'HIGH',
                'sources': ['Passive DNS', 'Active Brute-force']
            })
        
        return verified
