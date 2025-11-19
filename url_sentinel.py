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
        print(f"{Colors.CYAN}[*] Analyzing: {self.url}{Colors.ENDC}")
        
        # 1. Basic Syntax
        if not self._validate_structure():
            return
            
        # 2. Character & Homograph Analysis
        self._check_homographs()
        
        # 3. Encoding Analysis
        self._check_encoding()

        # 4. Heuristic Analysis
        self._check_heuristics()

        # 5. Entropy Analysis
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
            
            domain_clean = self.domain.split(':')[0]
            domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
            
            if not re.match(domain_regex, domain_clean) and not self._is_ip_address(domain_clean):
                 self.findings.append((Colors.WARNING, "WARNING", "Domain structure looks unusual."))
                 self.risk_score += 1
            return True
        except Exception:
            return False

    def _is_ip_address(self, domain):
        try:
            socket.inet_aton(domain)
            return True
        except socket.error:
            return False

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
        if self._is_ip_address(domain_clean):
            self.findings.append((Colors.WARNING, "SUSPICIOUS", "IP address used as domain."))
            self.risk_score += 2

        if len(domain_clean.split('.')) > 4:
            self.findings.append((Colors.WARNING, "SUSPICIOUS", "High number of subdomains."))
            self.risk_score += 1

        keywords = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'bonus']
        if any(k in domain_clean.lower() for k in keywords):
            self.findings.append((Colors.WARNING, "SUSPICIOUS", "Sensitive keyword in domain."))
            self.risk_score += 2
            
        if '@' in self.url:
             self.findings.append((Colors.FAIL, "HIGH RISK", "URL contains '@' symbol."))
             self.risk_score += 4

    def _check_entropy(self):
        domain_clean = self.domain.split(':')[0]
        probs = [n_x / len(domain_clean) for n_x in Counter(domain_clean).values()]
        entropy = -sum(p * math.log(p, 2) for p in probs)
        if entropy > 4.0:
            self.findings.append((Colors.BLUE, "INFO", f"High Entropy ({entropy:.2f}). Possible generated domain."))
            self.risk_score += 1

    def _print_report(self):
        if not self.findings:
            print(f"{Colors.GREEN}[+] Verdict: CLEAN{Colors.ENDC}")
        else:
            for color, level, msg in self.findings:
                print(f"{color}[{level}] {msg}{Colors.ENDC}")
            
            if self.risk_score >= 4:
                print(f"{Colors.FAIL}{Colors.BOLD}[!] Verdict: HIGH PROBABILITY OF MALICE (Score: {self.risk_score}){Colors.ENDC}")
            elif self.risk_score > 0:
                print(f"{Colors.WARNING}[!] Verdict: SUSPICIOUS (Score: {self.risk_score}){Colors.ENDC}")
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
    print(f"{Colors.BLUE}        Defensive URL Static Analysis Tool for Kali Linux{Colors.ENDC}")
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
                        time.sleep(0.5) # Small delay for readability
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error reading file: {e}{Colors.ENDC}")
            
    input(f"\n{Colors.CYAN}Press Enter to return to menu...{Colors.ENDC}")

def show_help():
    print(f"\n{Colors.BOLD}--- HELP / ABOUT ---{Colors.ENDC}")
    print("1. This tool performs static analysis on URLs.")
    print("2. It does NOT connect to the URL, making it safe to run on malware links.")
    print("3. It detects Homographs (Fake letters), High Entropy (Random names), and Phishing keywords.")
    print("\nAuthor: URL Sentinel User")
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
