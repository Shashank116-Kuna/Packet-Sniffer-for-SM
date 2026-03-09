# Advanced Packet Sniffer & ARP Spoofing Detector

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-Packet%20Crafting-orange.svg)](https://scapy.net/)

**Real-time network monitoring tool that detects ARP spoofing (poisoning) attacks using Scapy.** 

Built for **educational purposes** and **defensive security** on networks you own or have permission to monitor. Identifies Man-in-the-Middle (MitM) attempts by tracking IP-MAC mapping changes and MAC reuse.

## 🚀 Features
- **Live Packet Sniffing**: Captures ARP, TCP, UDP, ICMP traffic with colored terminal display [file:1]
- **Dual Detection Logic**:
  - MAC changes for known IPs (classic ARP poisoning)
  - Single MAC claiming multiple IPs (multi-victim attacks) [file:1]
- **Visual Alerts**: Color-coded banners for spoofing detections
- **Persistent Logging**: `arp_alert_log.txt` with timestamps, old/new MACs, session stats
- **Interactive Interface Selection**: Lists and lets you pick network interfaces
- **Graceful Stats**: Session summary (packets, alerts, trust table) on Ctrl+C

## 📋 Demo Output:
[!] ARP SPOOFING ALERT DETECTED !
IP Address : 192.168.1.1
Old MAC : aa:bb:cc:dd:ee:ff
New MAC : 00:11:22:33:44:55
Alert : MAC ADDRESS CHANGED for IP 192.168.1.1!
Time : 14:23:45
→ Logged to: arp_alert_log.txt                                                                                                            
## 🛠️ Requirements
- Python 3.6+
- Scapy: `pip install scapy`
- **Root/admin privileges** for packet capture (`sudo python3 arp_sniffer.py`)

## ⚠️ Ethical & Legal Disclaimer
- **EDUCATIONAL/DEFENSIVE USE ONLY** [file:1]
- Use **ONLY** on networks you **OWN** or have **WRITTEN PERMISSION** to monitor
- Unauthorized use may violate CFAA/laws and ToS
- Author not liable for misuse

## 🚀 Quick Start
1. Clone repo: `git clone <your-repo>`
2. Install: `pip install scapy`
3. Run: `sudo python3 arp_sniffer.py`
4. Select interface (e.g., eth0, wlan0)
5. Monitor output; Ctrl+C for stats

## 🔧 Customization
- Edit `LOG_FILE` constant for log path
- Modify colors in `Color` class
- Extend `process_packet()` for custom protocols

## 📊 Detection Logic
1. Builds `ip_mac_table` from initial ARP replies
2. On new replies: Compare sender MAC vs. known
3. **Alert** on mismatch or MAC reuse
4. Updates table to continue monitoring [file:1]

## Author
Shashank Kuna   
🔗 [LinkedIn](https://www.linkedin.com/in/shashank-kuna-7781b1359/) | [GitHub](https://github.com/Shashank116-Kuna)

## License
MIT - Free for educational/defensive use with attribution.
 
