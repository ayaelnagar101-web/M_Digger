"""
Professional Report Generator (JSON + Markdown)
"""
import json
import os
from datetime import datetime
from colorama import Fore, Style

class ReportGenerator:
    """Generate VAPT-compliant reports"""
    
    RISK_COLORS = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢',
        'INFO': '🔵'
    }
    
    def __init__(self, findings, output_dir):
        self.findings = findings
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.target = findings['target']
    
    def generate(self):
        """Generate both JSON and Markdown reports"""
        print(f"{Fore.BLUE}[*] Generating reports...{Style.RESET_ALL}")
        
        # Generate JSON
        json_path = os.path.join(self.output_dir, f"{self.target}_{self.timestamp}.json")
        with open(json_path, 'w') as f:
            json.dump(self.findings, f, indent=2, default=str)
        print(f"  {Fore.GREEN}[+] JSON report saved: {json_path}{Style.RESET_ALL}")
        
        # Generate Markdown
        md_path = os.path.join(self.output_dir, f"{self.target}_{self.timestamp}.md")
        md_content = self._generate_markdown()
        with open(md_path, 'w') as f:
            f.write(md_content)
        print(f"  {Fore.GREEN}[+] Markdown report saved: {md_path}{Style.RESET_ALL}")
        
        return json_path, md_path
    
    def _generate_markdown(self):
        """Generate Markdown report content"""
        md = []
        
        # Header
        md.append(f"# Web Reconnaissance Report")
        md.append(f"**Target:** {self.target}")
        md.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**Mode:** {self.findings.get('mode', 'Unknown')}")
        md.append("")
        
        # Executive Summary
        md.append("## 📋 Executive Summary")
        md.append("")
        
        risk_summary = self.findings.get('risk_assessment', {}).get('summary', {})
        md.append(f"- **Critical Findings:** {risk_summary.get('critical', 0)}")
        md.append(f"- **High Findings:** {risk_summary.get('high', 0)}")
        md.append(f"- **Medium Findings:** {risk_summary.get('medium', 0)}")
        md.append(f"- **Low Findings:** {risk_summary.get('low', 0)}")
        md.append(f"- **Overall Risk:** {risk_summary.get('overall_risk', 'Unknown')}")
        md.append("")
        
        # Passive Intelligence Section
        if 'passive' in self.findings:
            md.append("## 🔍 Passive Intelligence")
            md.append("")
            
            # Shodan Findings
            if 'shodan' in self.findings['passive']:
                shodan = self.findings['passive']['shodan']
                md.append("### 📡 Shodan Findings")
                md.append(f"- **IP:** {shodan.get('ip', 'Unknown')}")
                md.append(f"- **Organization:** {shodan.get('org', 'Unknown')}")
                md.append(f"- **Open Ports:** {len(shodan.get('ports', []))}")
                md.append("")
                
                if shodan.get('vulns'):
                    md.append("#### Vulnerabilities Found")
                    for vuln in shodan['vulns']:
                        md.append(f"- {self.RISK_COLORS['HIGH']} {vuln}")
                    md.append("")
            
            # VirusTotal Findings
            if 'virustotal' in self.findings['passive']:
                vt = self.findings['passive']['virustotal']
                md.append("### 🦠 VirusTotal Findings")
                md.append(f"- **Subdomains Found:** {len(vt.get('subdomains', []))}")
                md.append(f"- **Reputation:** {vt.get('reputation', 'Unknown')}")
                md.append("")
            
            # Hunter.io Findings
            if 'hunter' in self.findings['passive']:
                hunter = self.findings['passive']['hunter']
                md.append("### 📧 Email Discovery (Hunter.io)")
                md.append(f"- **Emails Found:** {len(hunter.get('emails', []))}")
                if hunter.get('pattern'):
                    md.append(f"- **Email Pattern:** `{hunter['pattern']}`")
                md.append("")
                
                if hunter.get('emails'):
                    md.append("| Email | Type | Confidence |")
                    md.append("|-------|------|------------|")
                    for email in hunter['emails'][:10]:
                        md.append(f"| {email['email']} | {email['type']} | {email['confidence']}% |")
                    md.append("")
            
            # SSL Certificate
            if 'ssl' in self.findings['passive']:
                ssl = self.findings['passive']['ssl']
                md.append("### 🔒 SSL Certificate Analysis")
                md.append(f"- **SANs Found:** {len(ssl.get('sans', []))}")
                
                if ssl.get('vulnerabilities'):
                    md.append("")
                    md.append("#### Certificate Issues")
                    for vuln in ssl['vulnerabilities']:
                        md.append(f"- {self.RISK_COLORS['MEDIUM']} {vuln}")
                md.append("")
        
        # Active Reconnaissance Section
        if 'active' in self.findings:
            md.append("## 🎯 Active Reconnaissance")
            md.append("")
            
            # Port Scan Results
            if 'ports' in self.findings['active']:
                ports = self.findings['active']['ports']
                md.append(f"### 🌐 Open Ports ({len(ports)} found)")
                md.append("")
                md.append("| Port | Service | Banner |")
                md.append("|------|---------|--------|")
                for port_info in ports:
                    banner = port_info.get('banner', 'N/A')[:30]
                    md.append(f"| {port_info['port']} | {port_info.get('service', 'Unknown')} | {banner} |")
                md.append("")
            
            # Directory Fuzzing
            if 'directories' in self.findings['active']:
                dirs = self.findings['active']['directories']
                md.append(f"### 📁 Discovered Paths ({len(dirs)} found)")
                md.append("")
                md.append("| Path | Status | Title |")
                md.append("|------|--------|-------|")
                for dir_info in dirs[:20]:
                    title = dir_info.get('title', 'N/A')[:30]
                    md.append(f"| {dir_info['path']} | {dir_info['status']} | {title} |")
                md.append("")
        
        # Verified Findings
        if 'verified' in self.findings and self.findings['verified']:
            md.append("## ✅ Verified Findings (High Confidence)")
            md.append("")
            for finding in self.findings['verified']:
                md.append(f"- **{finding['type'].upper()}:** {finding['value']}")
                md.append(f"  - Confidence: {finding['confidence']}")
                md.append(f"  - Sources: {', '.join(finding['sources'])}")
            md.append("")
        
        # Risk Assessment
        if 'risk_assessment' in self.findings:
            md.append("## ⚠️ Risk Assessment")
            md.append("")
            
            for finding in self.findings['risk_assessment'].get('findings', []):
                risk_icon = self.RISK_COLORS.get(finding['risk'], '⚪')
                md.append(f"### {risk_icon} {finding['risk']} - {finding['type']}")
                md.append(f"- **Source:** {finding['source']}")
                md.append(f"- **Detail:** {finding['detail']}")
                md.append("")
        
        # Recommendations
        md.append("## 🛡️ Recommendations")
        md.append("")
        md.append("1. Review and close unnecessary open ports")
        md.append("2. Update services with known CVEs to latest versions")
        md.append("3. Implement missing security headers")
        md.append("4. Remove exposed backup files and admin panels")
        md.append("5. Enable WHOIS privacy protection if not already enabled")
        md.append("")
        
        # Footer
        md.append("---")
        md.append(f"*Report generated by Advanced Web Reconnaissance Tool*")
        md.append(f"*{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        
        return '\n'.join(md)
