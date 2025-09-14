# 🚀 PCAP Threat Analyzer

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)


A powerful automated threat analysis tool for PCAP files that detects suspicious network activities, analyzes potential security threats, and generates detailed reports with visualizations.

## 🌟 Features

- 🔍 **Automated PCAP Analysis**: Scans network traffic for suspicious patterns
- 🚨 **Threat Detection**: Identifies various types of network threats
- 📊 **Visual Reports**: Generates intuitive charts and graphs
- 📧 **Email Alerts**: Sends detailed reports via email
- 🕵️ **IP Reputation Check**: Verifies IPs against VirusTotal database
- 📈 **Behavioral Analysis**: Detects beaconing, port scanning, and more

## 📋 Supported Threat Types

- Beaconing detection
- Unusual port activity
- Mail spam analysis
- Data exfiltration attempts
- Suspicious IP correlation

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Madhavv13/Automate-pcap-threat-analyzer.git
   cd Automate-pcap-threat-analyzer
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## ⚙️ Configuration

1. **VirusTotal API**:
   - Get your API key from [VirusTotal](https://www.virustotal.com/)
   - Update `VT_API_KEY` in `automate.py`

2. **Email Alerts**:
   - Configure SMTP settings in `automate.py`
   - For Gmail, use an App Password if 2FA is enabled

## 🚀 Usage

1. Place your PCAP files in the `datasets` directory
2. Run the analyzer:
   ```bash
   python automate.py
   ```
3. Check your email for the detailed threat report

## 📊 Sample Output

The analyzer generates:
- Interactive HTML reports
- Visual charts of threat distribution
- Top malicious IP addresses
- Detailed threat categorization




