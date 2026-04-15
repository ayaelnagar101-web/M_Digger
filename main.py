#!/usr/bin/env python3
"""
Advanced Web Reconnaissance Tool - VAPT Edition
Multi-Source Passive Intelligence + WAF-Evasive Active Scanning
"""

import argparse
import sys
import os
import socket
import json
from datetime import datetime
from colorama import init, Fore, Style
from pathlib import Path

# Initialize colorama
init(autoreset=True)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from config import Config
from modules.stealth_requester import StealthRequester
from modules.api_manager import APIManager
from modules.ssl_analyzer import SSLAnalyzer
from modules.port_scanner import PortScanner
from modules.banner_grabber import BannerGrabber
from modules.dir_fuzzer import DirectoryFuzzer
from modules.subdomain_enum import SubdomainEnumerator
from modules.report_generator import ReportGenerator
from utils.risk_engine import RiskEngine
from utils.correlation_engine import CorrelationEngine
from modules.waf_detector import WAFDetector

def print_banner():
    """Display tool banner"""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}╔══════════════════════════════════════════════════════════════════╗
║     ADVANCED WEB RECONNAISSANCE TOOL - VAPT EDITION               ║
║     Multi-Source Intelligence + WAF Evasion                       ║
║     Passive → Active → Verified                                   ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def check_api_status():
    """Display configured APIs"""
    available, missing = Config.validate_api_keys()
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[API Status]{Style.RESET_ALL}")
    if available:
        print(f"  {Fore.GREEN}[✓] Available: {', '.join(available)}{Style.RESET_ALL}")
    if missing:
        print(f"  {Fore.YELLOW}[!] Missing: {', '.join(missing)}{Style.RESET_ALL}")
    print()

def resolve_target(target):
    """Resolve domain to IP"""
    try:
        return socket.gethostbyname(target)
    except:
        return None

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Web Reconnaissance Tool - VAPT Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("--mode", choices=["passive", "active", "full"], 
                       default="full", help="Reconnaissance mode")
    parser.add_argument("--stealth", action="store_true", 
                       help="Enable stealth mode (delays, rotation, WAF evasion)")
    parser.add_argument("--wordlist", default="wordlists/common.txt",
                       help="Path to wordlist file")
    parser.add_argument("--output", default="reports/",
                       help="Output directory")
    parser.add_argument("--no-verify", action="store_true",
                       help="Skip correlation verification")
    
    args = parser.parse_args()
    
    print_banner()
    check_api_status()
    
    # Initialize components
    stealth = StealthRequester() if args.stealth else None
    api_manager = APIManager()
    risk_engine = RiskEngine()
    correlation = CorrelationEngine()
    
    # Resolve target
    target_ip = resolve_target(args.target)
    
    print(f"{Fore.GREEN}{Style.BRIGHT}[Target Information]{Style.RESET_ALL}")
    print(f"  Target: {args.target}")
    print(f"  Resolved IP: {target_ip or 'Resolution failed'}")
    print(f"  Mode: {args.mode}")
    print(f"  Stealth: {'Enabled' if args.stealth else 'Disabled'}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    # Storage for all findings
    findings = {
        "target": args.target,
        "resolved_ip": target_ip,
        "timestamp": datetime.now().isoformat(),
        "mode": args.mode,
        "stealth_enabled": args.stealth,
        "passive": {},
        "active": {},
        "verified": [],
        "risk_assessment": {}
    }

    # WAF Detection (if stealth mode)
if args.stealth and Config.WAF_DETECTION:
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}[WAF Detection]{Style.RESET_ALL}")
    
    # Use the new wafw00f-based detector
    waf_detector = WAFDetector(args.target)
    waf_detected = waf_detector.detect()
    findings["waf_detected"] = waf_detected
    
    if waf_detected:
        print(f"\n  {Fore.YELLOW}[!] Recommended evasion strategies:{Style.RESET_ALL}")
        strategies = waf_detector.get_evasion_strategy()
        for strategy in strategies:
            print(f"      - {strategy}")
        findings["waf_evasion_strategies"] = strategies
    
    
    # ===== PHASE 1: PASSIVE INTELLIGENCE (API-Based) =====
    if args.mode in ["passive", "full"]:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}[PHASE 1: Passive Intelligence Gathering]{Style.RESET_ALL}")
        print("-" * 60)
        
        # Shodan Query
        if target_ip:
            shodan_data = api_manager.query_shodan(target_ip)
            if shodan_data:
                findings["passive"]["shodan"] = shodan_data
        
        # VirusTotal Query
        vt_data = api_manager.query_virustotal(args.target)
        if vt_data:
            findings["passive"]["virustotal"] = vt_data
        
        # Censys Query
        censys_data = api_manager.query_censys(args.target)
        if censys_data:
            findings["passive"]["censys"] = censys_data
        
        # Hunter.io Query
        hunter_data = api_manager.query_hunter(args.target)
        if hunter_data:
            findings["passive"]["hunter"] = hunter_data
        
        # SSL Certificate Analysis
        print(f"\n{Fore.CYAN}[*] Analyzing SSL Certificate...{Style.RESET_ALL}")
        ssl_analyzer = SSLAnalyzer(args.target)
        ssl_data = ssl_analyzer.analyze()
        findings["passive"]["ssl"] = ssl_data
        
        # Aggregate passive findings
        aggregated = api_manager.aggregate_passive_findings()
        findings["passive"]["aggregated"] = aggregated
        
        print(f"\n{Fore.GREEN}[+] Passive Intelligence Summary:{Style.RESET_ALL}")
        print(f"  Subdomains discovered: {len(aggregated['subdomains'])}")
        print(f"  IPs identified: {len(aggregated['ips'])}")
        print(f"  Emails found: {len(aggregated['emails'])}")
    
    # ===== PHASE 2: ACTIVE SCANNING (WAF-Evasive) =====
    if args.mode in ["active", "full"]:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}[PHASE 2: Active Reconnaissance]{Style.RESET_ALL}")
        print("-" * 60)
        
        # Subdomain Enumeration
        print(f"\n{Fore.CYAN}[*] Enumerating subdomains...{Style.RESET_ALL}")
        sub_enum = SubdomainEnumerator(args.target, args.wordlist)
        if args.stealth:
            sub_enum.set_stealth_mode(stealth)
        subdomains = sub_enum.enumerate()
        findings["active"]["subdomains"] = subdomains
        
        # Port Scanning
        print(f"\n{Fore.CYAN}[*] Scanning ports...{Style.RESET_ALL}")
        port_scanner = PortScanner(target_ip or args.target)
        if args.stealth:
            port_scanner.set_stealth_mode(True)
        open_ports = port_scanner.scan()
        findings["active"]["ports"] = open_ports
        
        # Banner Grabbing
        if open_ports:
            print(f"\n{Fore.CYAN}[*] Grabbing banners...{Style.RESET_ALL}")
            banner_grabber = BannerGrabber(target_ip or args.target, open_ports)
            banners = banner_grabber.grab()
            findings["active"]["banners"] = banners
        
        # Directory Fuzzing
        print(f"\n{Fore.CYAN}[*] Fuzzing directories...{Style.RESET_ALL}")
        dir_fuzzer = DirectoryFuzzer(args.target, args.wordlist)
        if args.stealth:
            dir_fuzzer.set_stealth_mode(stealth)
        directories = dir_fuzzer.fuzz()
        findings["active"]["directories"] = directories
    
    # ===== PHASE 3: VERIFICATION & CORRELATION =====
    if not args.no_verify and args.mode == "full":
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}[PHASE 3: Verification & Correlation]{Style.RESET_ALL}")
        print("-" * 60)
        
        verified = correlation.verify_findings(findings)
        findings["verified"] = verified
        
        if verified:
            print(f"  {Fore.GREEN}[✓] {len(verified)} findings verified with high confidence{Style.RESET_ALL}")
    
    # ===== PHASE 4: RISK ASSESSMENT =====
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}[PHASE 4: Risk Assessment]{Style.RESET_ALL}")
    print("-" * 60)
    
    risk_assessment = risk_engine.assess(findings)
    findings["risk_assessment"] = risk_assessment
    
    print(f"  Critical: {risk_assessment['summary']['critical']}")
    print(f"  High: {risk_assessment['summary']['high']}")
    print(f"  Medium: {risk_assessment['summary']['medium']}")
    print(f"  Low: {risk_assessment['summary']['low']}")
    
    # ===== GENERATE REPORTS =====
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}[Generating Reports]{Style.RESET_ALL}")
    print("-" * 60)
    
    os.makedirs(args.output, exist_ok=True)
    report_gen = ReportGenerator(findings, args.output)
    json_path, md_path = report_gen.generate()
    
    print(f"\n{Fore.GREEN}{Style.BRIGHT}[✓] Reconnaissance Complete!{Style.RESET_ALL}")
    print(f"  JSON Report: {json_path}")
    print(f"  Markdown Report: {md_path}")
    print(f"  Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)
