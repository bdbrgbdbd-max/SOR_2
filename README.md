# SRO v2.0: Strategic Reconnaissance Operations

**SRO** (Strategic Reconnaissance Operations) is the ultimate OSINT and Cyber Intelligence platform, designed for advanced security professionals. It transforms traditional information gathering into a strategic, offensive operation, providing deep insights and actionable intelligence for penetration testing and digital forensics.

## 🚀 Features Overview

SRO v2.0 integrates over 25 advanced modules, categorized for clarity:

### Section One: Offensive Reconnaissance & Vulnerability Mapping

This section is specialized in identifying and mapping potential attack vectors and vulnerabilities in the target's infrastructure.

1.  **Vulnerability Mapping (CVE):** Automatically links open services (e.g., Apache, Nginx) to known Common Vulnerabilities and Exposures (CVEs).
2.  **Exploit Finder:** Searches Exploit-DB and GitHub for ready-to-use exploit code for discovered CVEs.
3.  **Cloudflare Bypass Pro:** Advanced techniques (historical DNS, SSL certificates) to uncover the real Origin IP hidden behind Cloudflare, Akamai, or other CDNs/WAFs.
4.  **WAF/CDN Detection:** Quickly identifies the type of protection (WAF/CDN) used by the target.
5.  **Offensive DNS Intel:** Deep analysis of DNS records (MX, TXT, SPF) to find misconfigurations exploitable for Phishing or Domain Hijacking.
6.  **Zero-Day Simulation:** Simulates deep fuzzing and structural analysis to identify potential zero-day candidates (unpatched weaknesses).
7.  **Vulnerability Pipeline:** Scans a range of targets to classify them as "Easy Targets" based on the severity of their open vulnerabilities.

### Section Two: Deep Intelligence & Behavioral Analysis

This section focuses on deep-level intelligence gathering, behavioral profiling, and advanced forensic analysis.

1.  **AI Phishing Engine:** Uses AI to generate highly personalized and convincing spear-phishing messages based on the target's collected profile.
2.  **Hacker's Trap (Canary Tokens):** Generates professional tracking links to capture the target's real IP, device details, and precise location upon click.
3.  **Credential Intel:** Deep dark web search to retrieve actual leaked passwords (plaintext or hash) associated with the target's email or username.
4.  **Stylometry Analysis:** Attempts to link anonymous accounts by analyzing the unique writing style (stylometry) of the target's public posts.
5.  **Decentralized Identity Linking:** Links traditional identities (email/username) to complex decentralized identities (DID) and crypto wallet addresses.
6.  **Media Forensics (EXIF):** Extracts hidden metadata (GPS coordinates, device info) from images and documents.
7.  **Supply Chain Mapping:** Analyzes the target's software dependencies and third-party services to map potential supply chain attack vectors.

### Section Three: System & Reporting

This section covers the core functionality, system setup, and professional reporting.

1.  **System-Wide Tool:** SRO is installed as a system command (`sro`) on Kali Linux, allowing execution from any directory.
2.  **Silent Monitoring:** Continuous, background monitoring of the target with instant alerts and report delivery via Telegram.
3.  **Professional Reporting:** Generates comprehensive PDF reports and interactive visual graphs for all investigations.
4.  **Physical Security Intel:** Simulates analysis of physical security weaknesses (CCTV blind spots, entry points) based on geographical data.

## 🛠️ Installation (Kali Linux / Debian)

SRO is designed to be installed as a system-wide command.

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/YOUR_USERNAME/SRO.git
    cd SRO
    ```
2.  **Run the Installer:**
    ```bash
    chmod +x install.sh
    sudo ./install.sh
    ```
    *The installer will automatically install all required Python dependencies from `requirements.txt` and place the executable in `/usr/local/bin/sro`.*

## ⚙️ Usage

Run the tool from any terminal:

```bash
sro
```

### Configuration

Before running any advanced features, you **MUST** configure your API keys in the **Settings & Customization** menu (Option 7).

| API Key | Purpose |
| :--- | :--- |
| `openai` | AI Profiling, Phishing AI Engine |
| `shodan`, `censys`, `zoomeye` | Infrastructure & Vulnerability Intel |
| `leakcheck` | Deep Dark Web & Credential Intel |
| `telegram_token`, `telegram_chat_id` | Silent Monitoring & Report Delivery |

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for educational purposes, security research, and authorized penetration testing only. The developers are not responsible for any misuse or damage caused by this software. Use responsibly and legally.
