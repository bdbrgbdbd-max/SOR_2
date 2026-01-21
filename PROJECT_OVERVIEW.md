# SRO v2.0: Strategic Reconnaissance Operations

**SRO** (Strategic Reconnaissance Operations) is an advanced, all-in-one OSINT and Cyber Intelligence platform designed for professional security researchers, penetration testers, and digital forensic investigators. It combines traditional open-source intelligence gathering with cutting-edge offensive reconnaissance features, AI-powered analysis, and advanced threat mapping.

This tool is a system-wide utility, installable on Kali Linux and similar distributions, allowing execution from any terminal with the simple `sro` command.

## 🚀 Features

SRO v2.0 is the culmination of multiple development stages, integrating over 20 advanced features:

| Category | Key Features |
| :--- | :--- |
| **Offensive Recon** | Vulnerability Mapping (CVE), Exploit Finder, Cloudflare Bypass Pro, Offensive DNS Intel, WAF/CDN Detection. |
| **Advanced Intelligence** | Zero-Day Simulation, Supply Chain Mapping, Persistence Analysis, Decentralized Identity Linking, Physical Security Intel. |
| **AI & Behavioral** | AI-Powered Profiling, Phishing AI Engine (Spear Phishing Email Generation), Stylometry Analysis. |
| **Core OSINT** | Email/Username/IP/Phone Intel, Dark Web Breach Check, Crypto Wallet Tracking, Silent Monitoring (Telegram). |
| **Forensics & Reporting** | Media Forensics (EXIF), Interactive Visual Graphs, Timeline Analysis, Professional PDF Report Generation. |

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
