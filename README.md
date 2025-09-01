# XILLEN OSINT Framework

Advanced Open Source Intelligence gathering tool for comprehensive target reconnaissance and intelligence collection.

## 🚀 Features

- **Domain Analysis**: WHOIS lookup, DNS enumeration, subdomain discovery
- **Network Reconnaissance**: Port scanning, service detection
- **Email Harvesting**: Automated email discovery from web pages
- **Social Media OSINT**: Profile discovery across major platforms
- **Breach Intelligence**: Check for compromised accounts
- **Threat Intelligence**: Integration with VirusTotal, AbuseIPDB
- **Shodan Integration**: Internet-connected device discovery
- **Comprehensive Reporting**: JSON export with detailed findings

## 🛠️ Installation

```bash
git clone https://github.com/yourusername/xillen-osint.git
cd xillen-osint
pip install -r requirements.txt
```

## 📋 Prerequisites

- Python 3.7+
- Internet connection
- API keys for enhanced functionality (optional):
  - Shodan API key
  - VirusTotal API key
  - AbuseIPDB API key

## 🎯 Usage

### Basic Usage
```bash
python xillen_osint.py example.com
```

### With API Keys
```bash
python xillen_osint.py example.com --shodan-key YOUR_SHODAN_KEY --virustotal-key YOUR_VT_KEY
```

### Quick Scan
```bash
python xillen_osint.py example.com --quick
```

## 📊 Output

The tool generates comprehensive JSON reports containing:

- Domain registration information
- DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
- Discovered subdomains
- Open ports and services
- Email addresses
- Social media profiles
- Breach information
- Threat intelligence data

## 🔧 Configuration

### API Keys Setup

1. **Shodan**: Get your API key from [shodan.io](https://account.shodan.io/)
2. **VirusTotal**: Register at [virustotal.com](https://www.virustotal.com/)
3. **AbuseIPDB**: Sign up at [abuseipdb.com](https://www.abuseipdb.com/)

### Environment Variables (Optional)
```bash
export SHODAN_API_KEY="your_shodan_key"
export VIRUSTOTAL_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
```

## 📈 Performance

- **Concurrent Processing**: Multi-threaded subdomain discovery and port scanning
- **Rate Limiting**: Respectful scanning with configurable delays
- **Timeout Management**: Prevents hanging on unresponsive targets
- **Error Handling**: Graceful failure recovery

## 🛡️ Legal Notice

This tool is for authorized security testing and research purposes only. Users are responsible for:

- Obtaining proper authorization before scanning targets
- Complying with applicable laws and regulations
- Respecting rate limits and terms of service
- Using results ethically and responsibly

## 🔍 Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                    XILLEN OSINT FRAMEWORK                    ║
║              Advanced Intelligence Gathering Tool            ║
╚══════════════════════════════════════════════════════════════╝

Target: example.com
Started: 2024-01-15 14:30:25

[*] Starting domain analysis...
[+] Domain information collected
[*] Starting DNS enumeration...
[+] A records found: 1
[+] MX records found: 2
[*] Starting subdomain discovery...
[+] Subdomain found: www.example.com
[+] Subdomain found: mail.example.com
[*] Starting port scanning...
[+] Open port found: 80
[+] Open port found: 443
[*] Starting email harvesting...
[+] Email found: admin@example.com
[+] Email found: support@example.com
[*] Starting social media OSINT...
[+] Twitter profile found
[+] LinkedIn profile found
[*] Starting breach check...
[!] Breach found for admin@example.com: 3 occurrences
[*] Generating comprehensive report...
[+] Report saved to: xillen_osint_report_example.com_20240115_143045.json

╔══════════════════════════════════════════════════════════════╗
║                        OSINT SUMMARY                        ║
╚══════════════════════════════════════════════════════════════╝

Target: example.com
Subdomains Found: 2
Open Ports: 2
Emails Found: 2
Social Media Profiles: 2
Breaches Found: 1
Report File: xillen_osint_report_example.com_20240115_143045.json

OSINT scan completed successfully!
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before conducting any security assessments.
