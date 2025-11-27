#!/usr/bin/env python3
import re
import sys
import os
import urllib.parse
import unicodedata
import math
import socket
import time
from collections import Counter

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'

class URLAnalyzer:
    def __init__(self, url):
        self.url = url.strip()
        self.parsed = None
        self.domain = ""
        self.risk_score = 0
        self.findings = []

    def analyze(self):
        print(f"{Colors.CYAN}[*] Starting Deep Analysis...{Colors.ENDC}")
        
        # 1. Basic Syntax
        if not self._validate_structure():
            return
        
        # 2. Masked Domain Detection (NEW - Works for ANY company)
        self._check_masked_domain()

        # 3. Typosquatting (Brands + Generic Keywords)
        self._check_typosquatting()

        # 4. File Extension Analysis
        self._check_file_extensions()

        # 5. Risky TLD Analysis
        self._check_risky_tlds()

        # 6. URL Shortener Detection
        self._check_shorteners()

        # 7. Port Analysis
        self._check_ports()

        # 8. Character & Homograph Analysis
        self._check_homographs()
        
        # 9. Encoding Analysis
        self._check_encoding()

        # 10. Heuristic Analysis
        self._check_heuristics()

        # 11. Entropy Analysis
        self._check_entropy()

        self._print_report()

    def _validate_structure(self):
        try:
            if not self.url.startswith(('http://', 'https://')):
                self.url = 'http://' + self.url
            
            self.parsed = urllib.parse.urlparse(self.url)
            self.domain = self.parsed.netloc
            
            if not self.domain:
                print(f"{Colors.FAIL}[!] Invalid URL structure.{Colors.ENDC}")
                return False
            return True
        except Exception:
            return False

    def _check_masked_domain(self):
        """
        Detects if a URL contains another domain inside it to confuse the user.
        Example: your-company.com.phishing.net
        This works for ANY target, not just big brands.
        """
        # Common TLDs that shouldn't appear in the middle of a domain
        common_tlds = ['.com', '.net', '.org', '.gov', '.edu', '.io', '.co']
        
        # Remove the actual TLD at the end to check the middle
        parts = self.domain.split('.')
        if len(parts) > 2:
            subdomain_part = ".".join(parts[:-2]) # Everything before the main domain
            
            for tld in common_tlds:
                if tld + "." in self.domain and not self.domain.endswith(tld):
                    self.findings.append((Colors.FAIL, "HIGH RISK", f"Masked Domain Detected: '{tld}' found in subdomain. (e.g., legitimate.com.evil.net)"))
                    self.risk_score += 5
                    return # Stop after finding one

    def _check_typosquatting(self):
        domain_clean = self.domain.split(':')[0].lower()
        leetspeak_map = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'}
        
        normalized_domain = domain_clean
        for char, replacement in leetspeak_map.items():
            normalized_domain = normalized_domain.replace(char, replacement)

        # 1. Specific Targets (Big Brands)
        targets = ['google', 'microsoft', 'facebook', 'apple', 'amazon', 'netflix', 'paypal', 'instagram', 'twitter', 'linkedin', 'whatsapp', 'binance']
        
        # 2. Generic Keywords (Applies to ANY website)
        # If someone sends you "s3cure-log1n.com", it is malicious regardless of the company.
        generic_keywords = ['login', 'secure', 'account', 'update', 'verify', 'admin', 'password', 'wallet', 'confirm', 'support', 'billing', 'invoice']
        
        all_checks = targets + generic_keywords

        for check in all_checks:
            if check in normalized_domain and check not in domain_clean:
                self.findings.append((Colors.FAIL, "HIGH RISK", f"Obfuscated Keyword Detected: '{check}' (hidden in '{domain_clean}')"))
                self.risk_score += 6
                return

    def _check_file_extensions(self):
        """Detects if the URL points to a dangerous file type."""
        dangerous_exts = ['.exe', '.dll', '.bat', '.cmd', '.sh', '.apk', '.iso', '.dmg', '.msi', '.vbs', '.scr', '.jar']
        path = self.parsed.path.lower()
        
        for ext in dangerous_exts:
            if path.endswith(ext):
                self.findings.append((Colors.FAIL, "HIGH RISK", f"Direct File Download Detected: {ext}"))
                self.risk_score += 5

    def _check_risky_tlds(self):
        """Checks for Top-Level Domains often used by malware."""
        risky_tlds = ['.zip', '.mov', '.gq', '.cf', '.tk', '.ml', '.ga', '.top', '.work', '.date', '.click', '.xyz', '.review', '.country', '.kim']
        
        for tld in risky_tlds:
            if self.domain.lower().endswith(tld):
                self.findings.append((Colors.WARNING, "SUSPICIOUS", f"Risky TLD Detected: {tld} (High abuse rate)"))
                self.risk_score += 2

    def _check_shorteners(self):
        """Detects known URL shorteners."""
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'tr.im']
        domain_base = self.domain.lower().split(':')[0]
        
        if domain_base in shorteners:
             self.findings.append((Colors.BLUE, "INFO", "URL Shortener Detected. Destination is hidden."))
             self.risk_score += 1

    def _check_ports(self):
        """Checks for non-standard ports."""
        if ':' in self.domain:
            try:
                port = int(self.domain.split(':')[1])
                if port not in [80, 443]:
                    self.findings.append((Colors.WARNING, "SUSPICIOUS", f"Non-Standard Port Detected: {port}"))
                    self.risk_score += 2
            except ValueError:
                pass

    def _check_homographs(self):
        try:
            idna_domain = self.domain.encode('idna').decode('utf-8')
            if self.domain != idna_domain:
                self.findings.append((Colors.WARNING, "SUSPICIOUS", f"IDN/Punycode Detected: {idna_domain}"))
                self.risk_score += 3
            
            scripts = set()
            for char in self.domain:
                if char in ['.', ':'] or char.isdigit(): continue
                try:
                    name = unicodedata.name(char)
                    scripts.add(name.split()[0])
                except: pass

            if len(scripts) > 1:
                self.findings.append((Colors.FAIL, "HIGH RISK", f"Mixed Scripts: {', '.join(scripts)}"))
                self.risk_score += 5
        except: pass

    def _check_encoding(self):
        if '%' in self.url:
            decoded = urllib.parse.unquote(self.url)
            if '%' in decoded:
                self.findings.append((Colors.WARNING, "SUSPICIOUS", "Double URL Encoding detected."))
                self.risk_score += 2

    def _check_heuristics(self):
        domain_clean = self.domain.split(':')[0]
        try:
            socket.inet_aton(domain_clean)
            self.findings.append((Colors.WARNING, "SUSPICIOUS", "IP address used as domain."))
            self.risk_score += 2
        except socket.error:
            pass
        
        # Check for hyphen abuse (common in generic phishing)
        if domain_clean.count('-') > 3:
             self.findings.append((Colors.WARNING, "SUSPICIOUS", "Excessive use of hyphens in domain."))
             self.risk_score += 2

        keywords = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'bonus', 'support', 'free', 'gift', 'signin', 'service']
        if any(k in domain_clean.lower() for k in keywords):
            self.findings.append((Colors.WARNING, "SUSPICIOUS", "Sensitive keyword in domain."))
            self.risk_score += 2

    def _check_entropy(self):
        domain_clean = self.domain.split(':')[0]
        probs = [n_x / len(domain_clean) for n_x in Counter(domain_clean).values()]
        entropy = -sum(p * math.log(p, 2) for p in probs)
        if entropy > 4.2:
            self.findings.append((Colors.BLUE, "INFO", f"High Entropy ({entropy:.2f}). Possible generated domain."))
            self.risk_score += 1

    def _print_report(self):
        print(f"\n{Colors.HEADER}--- ANALYSIS REPORT ---{Colors.ENDC}")
        
        print(f"{Colors.BOLD}[+] URL Details:{Colors.ENDC}")
        print(f"  • Protocol: {self.parsed.scheme.upper()}")
        print(f"  • Domain:   {self.domain}")
        parts = self.domain.split('.')
        if len(parts) > 1:
            print(f"  • TLD:      .{parts[-1]}")
        
        if self.parsed.path and self.parsed.path != "/":
            print(f"  • Path:     {self.parsed.path}")
        if self.parsed.query:
            print(f"  • Params:   {self.parsed.query}")
        print("-" * 40)
        
        # --- Findings Loop ---
        if not self.findings:
            print(f"{Colors.GREEN}[+] No suspicious indicators found.{Colors.ENDC}")
        else:
            for color, level, msg in self.findings:
                print(f"{color}[{level}] {msg}{Colors.ENDC}")
        
        print("-" * 40)

        # --- FINAL VERDICT ---
        print(f"{Colors.BOLD}[+] FINAL VERDICT:{Colors.ENDC}")
        
        if self.risk_score == 0:
            print(f"  {Colors.GREEN}● STATUS: SAFE{Colors.ENDC}")
            print(f"  {Colors.GREEN}● Analysis: No threats found. The URL structure looks standard.{Colors.ENDC}")
            print(f"  {Colors.BOLD}● Recommendation: Safe to proceed (but always be careful).{Colors.ENDC}")

        elif self.risk_score <= 2:
            print(f"  {Colors.WARNING}● STATUS: CAUTION (Low Risk){Colors.ENDC}")
            print(f"  {Colors.WARNING}● Analysis: Slight anomalies or tracking links detected.{Colors.ENDC}")
            print(f"  {Colors.BOLD}● Recommendation: Verify the source before clicking.{Colors.ENDC}")

        elif self.risk_score <= 4:
            print(f"  {Colors.WARNING}● STATUS: SUSPICIOUS (Moderate Risk){Colors.ENDC}")
            print(f"  {Colors.WARNING}● Analysis: Contains characteristics common in spam or soft phishing.{Colors.ENDC}")
            print(f"  {Colors.BOLD}● Recommendation: DO NOT enter passwords or personal info.{Colors.ENDC}")

        else:
            print(f"  {Colors.FAIL}● STATUS: DANGEROUS (High Risk){Colors.ENDC}")
            print(f"  {Colors.FAIL}● Analysis: Strong indicators of Phishing, Malware, or Scam.{Colors.ENDC}")
            print(f"  {Colors.BOLD}● Recommendation: DO NOT CLICK. Block this link immediately.{Colors.ENDC}")
        
        print(f"\n  (Technical Risk Score: {self.risk_score}/10)")
        print("-" * 40)

# --- MENU FUNCTIONS ---

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print(f"{Colors.HEADER}")
    print(r"""
  _   _ ____  _       ____  _____ _   _ _____ ___ _   _ _____ _     
 | | | |  _ \| |     / ___|| ____| \ | |_   _|_ _| \ | | ____| |    
 | | | | |_) | |     \___ \|  _| |  \| | | |  | ||  \| |  _| | |    
 | |_| |  _ <| |___   ___) | |___| |\  | | |  | || |\  | |___| |___ 
  \___/|_| \_\_____| |____/|_____|_| \_| |_| |___|_| \_|_____|_____|
    """)
    print(f"{Colors.BLUE}        Defensive URL Static Analysis Tool v3.2{Colors.ENDC}")
    print(f"{Colors.HEADER}================================================================{Colors.ENDC}")

def analyze_single():
    print(f"\n{Colors.BOLD}--- Single URL Analysis ---{Colors.ENDC}")
    url = input("Enter URL to scan: ")
    if url.strip():
        analyzer = URLAnalyzer(url)
        analyzer.analyze()
    input(f"\n{Colors.CYAN}Press Enter to return to menu...{Colors.ENDC}")

def analyze_file():
    print(f"\n{Colors.BOLD}--- Bulk File Analysis ---{Colors.ENDC}")
    path = input("Enter path to file (e.g., list.txt): ")
    
    if not os.path.exists(path):
        print(f"{Colors.FAIL}[!] File not found.{Colors.ENDC}")
    else:
        try:
            with open(path, 'r') as f:
                urls = f.readlines()
                print(f"{Colors.BLUE}[*] Loaded {len(urls)} URLs.{Colors.ENDC}\n")
                for url in urls:
                    if url.strip():
                        analyzer = URLAnalyzer(url)
                        analyzer.analyze()
                        time.sleep(0.5)
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error reading file: {e}{Colors.ENDC}")
            
    input(f"\n{Colors.CYAN}Press Enter to return to menu...{Colors.ENDC}")

def show_help():
    print(f"\n{Colors.BOLD}--- HELP / ABOUT ---{Colors.ENDC}")
    print("1. Universal Detection: Works on any URL, not just big brands.")
    print("2. Masked Domains: Detects 'company.com.badsite.net' patterns.")
    print("3. Generic Leetspeak: Detects 'l0gin', 's3cure' in any domain.")
    input(f"\n{Colors.CYAN}Press Enter to return to menu...{Colors.ENDC}")

def main_menu():
    while True:
        clear_screen()
        print_banner()
        print(f"{Colors.GREEN}[1]{Colors.ENDC} Analyze Single URL")
        print(f"{Colors.GREEN}[2]{Colors.ENDC} Analyze List from File")
        print(f"{Colors.GREEN}[3]{Colors.ENDC} Help / About")
        print(f"{Colors.GREEN}[4]{Colors.ENDC} Exit")
        print("")
        
        choice = input(f"{Colors.BOLD}Select an option (1-4): {Colors.ENDC}")
        
        if choice == '1':
            analyze_single()
        elif choice == '2':
            analyze_file()
        elif choice == '3':
            show_help()
        elif choice == '4':
            print(f"\n{Colors.FAIL}Exiting... Stay Safe!{Colors.ENDC}")
            sys.exit()
        else:
            print(f"\n{Colors.FAIL}Invalid option.{Colors.ENDC}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.FAIL}Force Exit.{Colors.ENDC}")
        sys.exit()
