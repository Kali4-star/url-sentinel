🛡️ URL SentinelURL Sentinel is a lightweight security tool for Kali Linux. It helps you check if a URL is safe, malicious, or a phishing attempt without actually visiting the link.
⚡ Features
Safe: Does not connect to the malicious server (Passive Analysis).
Smart: Detects "Homograph Attacks" (fake letters like googIe.com).
Fast: Can scan a single link or a list of 1000+ links instantly.
No Setup: Uses standard Python libraries. No installation errors.
📥 Installation Steps
Follow these 3 simple steps to get the tool running on your machine.
Step 1: Download the ToolOpen your terminal and clone the repository:git clone [https://github.com/YOUR_USERNAME/url-sentinel.git](https://github.com/YOUR_USERNAME/url-sentinel.git)
Step 2: Enter the FolderMove into the directory you just downloaded:cd url-sentinel
Step 3: Make it RunnableYou need to give the script permission to run (you only need to do this once):chmod +x url_sentinel.py
🚀 How to Run
Start the tool with this simple command:./url_sentinel.py
You will see the Main Menu:[1] Analyze Single URL
[2] Analyze List from File
[3] Help / About
[4] Exit
🔹 Option 1: Scan a Single LinkSelect 1 and hit Enter.Paste the URL you want to check (e.g., http://suspect-site.com).The tool will immediately show you the Risk Score and Verdict.
🔹 Option 2: Scan a List (Bulk Mode)If you have many URLs to check, do this:Create a text file (e.g., bad_links.txt) and paste your URLs inside (one per line).Run the tool and select Option 2.Type the filename: bad_links.txt.The tool will scan them all automatically.
📊 Understanding the ResultsThe tool gives a color-coded verdict for every URL:
🟢 CLEAN: No obvious threats found.
🟡 SUSPICIOUS: The URL has some weird traits (like bad keywords).
🔴 HIGH RISK: The URL is likely a phishing site or malware.
Example of a High Risk Result:
[SUSPICIOUS] IDN Detected: xn--googe-eba.com (Fake Google)
[HIGH RISK] Mixed Scripts: LATIN, CYRILLIC
[!] Verdict: HIGH PROBABILITY OF MALICE
⚠️ DisclaimerThis tool is for educational and defensive purposes only. Please use it responsible to protect yourself and others.
📄 LicenseMIT License - You are free to use, modify, and share this tool.
