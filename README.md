🛡️ URL SentinelURL Sentinel is a defensive static analysis tool designed for security researchers, penetration testers, and privacy enthusiasts. It analyzes URLs to detect suspicious patterns, phishing attempts, and obfuscation techniques without executing the link or sending requests to the target server.This "passive" approach makes it safe to use on potential malware links or suspected phishing sites, as it does not alert the attacker that their URL is being analyzed.🚀 Features1. 🎭 Homograph & IDN Attack DetectionDetects Internationalized Domain Name (IDN) spoofing checks. It identifies if a URL is using mixed character scripts (e.g., mixing Cyrillic and Latin characters) to trick users into believing they are visiting a legitimate site (like google.com vs g0ogle.com).2. 🎲 Entropy Analysis (DGA Detection)Calculates the Shannon Entropy of the domain name. High entropy scores often indicate:Domain Generation Algorithms (DGA) used by botnets.Randomly generated phishing subdomains.3. 🎣 Phishing Keyword HeuristicsScans for common social engineering keywords often found in phishing campaigns, such as:secure-loginverify-accountupdate-bankingbonus-claim4. 📦 Bulk File ScanningHave a long list of suspicious URLs? URL Sentinel can read a text file and analyze hundreds of URLs automatically, providing a rapid triage report.5. 🔍 Encoding & Obfuscation ChecksDetects Double URL Encoding (used to bypass WAFs).Flags the use of IP addresses instead of domain names.Detects dangerous hex characters or null bytes.🛠️ InstallationPrerequisitesPython 3.x (Pre-installed on Kali Linux)No external pip libraries required (uses standard libraries only).SetupClone the repository:git clone [https://github.com/YOUR_USERNAME/url-sentinel.git](https://github.com/YOUR_USERNAME/url-sentinel.git)
Navigate to the directory:cd url-sentinel
Make the script executable:chmod +x url_sentinel.py
💻 UsageRun the tool directly from the terminal:./url_sentinel.py
You will be presented with an interactive menu:  _   _ ____  _       ____  _____ _   _ _____ ___ _   _ _____ _     
 | | | |  _ \| |     / ___|| ____| \ | |_   _|_ _| \ | | ____| |    
 | | | | |_) | |     \___ \|  _| |  \| | | |  | ||  \| |  _| | |    
 | |_| |  _ <| |___   ___) | |___| |\  | | |  | || |\  | |___| |___ 
  \___/|_| \_\_____| |____/|_____|_| \_| |_| |___|_| \_|_____|_____|
    
        Defensive URL Static Analysis Tool for Kali Linux
================================================================
[1] Analyze Single URL
[2] Analyze List from File
[3] Help / About
[4] Exit
Option 1: Single URLEnter a URL manually to get an instant risk report.Option 2: Bulk AnalysisCreate a text file (e.g., suspects.txt) with one URL per line:[http://example.com](http://example.com)
[http://googIe.com.verify.info](http://googIe.com.verify.info)
[http://192.168.1.1/login](http://192.168.1.1/login)
Select Option 2 and provide the filename suspects.txt.📊 Sample Output[*] Analyzing: [http://googIe.com.verify-login.info](http://googIe.com.verify-login.info)
[WARNING] Domain structure looks unusual.
[SUSPICIOUS] IDN/Punycode Detected: xn--googe-eba.com.verify-login.info
[HIGH RISK] Mixed Scripts: LATIN, CYRILLIC
[SUSPICIOUS] Sensitive keyword in domain.
----------------------------------------
[!] Verdict: HIGH PROBABILITY OF MALICE (Score: 11)
🤝 ContributingContributions, issues, and feature requests are welcome!Fork the ProjectCreate your Feature Branch (git checkout -b feature/AmazingFeature)Commit your Changes (git commit -m 'Add some AmazingFeature')Push to the Branch (git push origin feature/AmazingFeature)Open a Pull Request⚠️ DisclaimerURL Sentinel is for educational and defensive purposes only. The author is not responsible for any misuse of this tool. It is designed to help security professionals and users identify potential threats. Always exercise caution when dealing with unknown URLs.📄 LicenseDistributed under the MIT License. See LICENSE for more information.
