#!/usr/bin/env python3
"""
================================================================================
  Advanced Packet Sniffer + ARP Spoofing Detector
  Author  : Cybersecurity Network Security Project
  Version : 1.0.0
  Python  : 3.x
  Library : Scapy
================================================================================

EDUCATIONAL / ETHICAL DISCLAIMER
----------------------------------
This tool is designed STRICTLY for:
  - Educational purposes (learning about ARP, packet sniffing, network security)
  - Defensive / monitoring use on networks you OWN or have EXPLICIT permission to monitor

Running this tool without authorization on networks you do not own may be:
  - Illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws
  - A violation of network policies and terms of service

The author and contributors accept NO responsibility for misuse of this tool.
Always obtain written permission before running this on any network.

================================================================================
BACKGROUND KNOWLEDGE
================================================================================

1. ARP (Address Resolution Protocol)
   ------------------------------------
   ARP is a Layer 2 (Data Link) protocol used to map an IP address (Layer 3)
   to a physical MAC address (Layer 2) on a local area network (LAN).

   How it works:
     - Host A wants to send data to IP 192.168.1.5
     - Host A broadcasts: "Who has 192.168.1.5? Tell 192.168.1.10"
     - Host B (owning 192.168.1.5) replies: "192.168.1.5 is at AA:BB:CC:DD:EE:FF"
     - Host A caches this IP-to-MAC mapping in its ARP table

   ARP is stateless and trustless — any host can send an ARP reply
   without being asked, and other hosts will accept and cache it.

2. ARP Spoofing / ARP Poisoning
   --------------------------------
   ARP Spoofing exploits the trust in ARP by:
     - Sending FAKE ARP replies to victim hosts
     - Mapping a legitimate IP to the ATTACKER'S MAC address
     - Redirecting network traffic through the attacker's machine

   Classic Man-in-the-Middle (MitM) Attack:
     Victim A thinks: "The router (192.168.1.1) has MAC XX:XX:XX:XX:XX:XX" (ATTACKER'S MAC)
     Victim B thinks: "Host A (192.168.1.100) has MAC XX:XX:XX:XX:XX:XX" (ATTACKER'S MAC)
     All traffic flows THROUGH the attacker who can read, modify, or drop packets.

3. Detection Logic
   ------------------
   This tool detects ARP spoofing by:
     - Building and continuously updating a trusted IP → MAC mapping table
     - On each ARP reply/broadcast, comparing the sender's MAC to the stored MAC
     - Alerting if:
         a) A new MAC claims ownership of a known IP (MAC change)
         b) An IP appears with a MAC already used by another IP (MAC reuse)
     - Logging all anomalies with timestamp, IP, old MAC, and new MAC

================================================================================
"""

import sys
import os
import time
import signal
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# Scapy import with graceful error handling
# ─────────────────────────────────────────────────────────────────────────────
try:
    from scapy.all import (
        sniff,
        ARP,
        Ether,
        get_if_list,
        conf,
        IP,
        TCP,
        UDP,
        ICMP
    )
    # Suppress Scapy's IPv6 routing warnings on some platforms
    conf.verb = 0
except ImportError:
    print("[ERROR] Scapy is not installed.")
    print("        Install it with: pip install scapy")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

LOG_FILE        = "arp_alert_log.txt"
BANNER          = """
╔══════════════════════════════════════════════════════════════════════╗
║     Advanced Packet Sniffer + ARP Spoofing Detector                 ║
║     Powered by Scapy | For Educational & Defensive Use Only         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

# ANSI color codes for terminal output
class Color:
    RESET   = "\033[0m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"


# ══════════════════════════════════════════════════════════════════════════════
# LOGGING MODULE
# ══════════════════════════════════════════════════════════════════════════════

def initialize_log():
    """
    Creates or opens the ARP alert log file.
    Writes a session header with timestamp so multiple runs
    are clearly separated in the log file.
    """
    with open(LOG_FILE, "a") as f:
        f.write("\n" + "=" * 70 + "\n")
        f.write(f"  SESSION STARTED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n")


def log_alert(ip: str, old_mac: str, new_mac: str, message: str):
    """
    Appends a suspicious ARP event to the log file.

    Parameters:
        ip      : The IP address involved in the anomaly
        old_mac : The previously trusted MAC for this IP
        new_mac : The newly observed (suspicious) MAC
        message : Human-readable description of the alert
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"[{timestamp}] ALERT\n"
        f"  IP      : {ip}\n"
        f"  Old MAC : {old_mac}\n"
        f"  New MAC : {new_mac}\n"
        f"  Detail  : {message}\n"
        f"  {'─' * 60}\n"
    )
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)


def log_session_end(total_packets: int, total_alerts: int):
    """
    Writes session summary statistics to the log file.
    """
    with open(LOG_FILE, "a") as f:
        f.write(f"\n[SESSION END] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Total Packets Captured : {total_packets}\n")
        f.write(f"  Total Alerts Generated : {total_alerts}\n")
        f.write("=" * 70 + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE SELECTION MODULE
# ══════════════════════════════════════════════════════════════════════════════

def get_available_interfaces() -> list:
    """
    Retrieves a list of all available network interfaces on the system
    using Scapy's built-in get_if_list() function.

    Returns:
        List of interface name strings
    """
    try:
        interfaces = get_if_list()
        return [iface for iface in interfaces if iface]
    except Exception as e:
        print(f"{Color.RED}[ERROR] Could not retrieve interfaces: {e}{Color.RESET}")
        return []


def display_interfaces(interfaces: list):
    """
    Prints all available network interfaces in a numbered, formatted list.
    """
    print(f"\n{Color.CYAN}{Color.BOLD}Available Network Interfaces:{Color.RESET}")
    print(f"  {'#':<5} {'Interface Name'}")
    print(f"  {'─' * 40}")
    for idx, iface in enumerate(interfaces, start=1):
        print(f"  {idx:<5} {iface}")
    print()


def select_interface(interfaces: list) -> str:
    """
    Prompts the user to select a network interface from the numbered list.
    Validates input and returns the chosen interface name.

    Parameters:
        interfaces : List of available interface name strings

    Returns:
        Selected interface name string
    """
    while True:
        try:
            choice = input(
                f"{Color.YELLOW}Enter interface number [1-{len(interfaces)}]: {Color.RESET}"
            ).strip()
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                selected = interfaces[idx]
                print(f"\n{Color.GREEN}[+] Selected interface: {Color.BOLD}{selected}{Color.RESET}\n")
                return selected
            else:
                print(f"{Color.RED}  Invalid selection. Choose between 1 and {len(interfaces)}.{Color.RESET}")
        except ValueError:
            print(f"{Color.RED}  Please enter a numeric value.{Color.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}[!] Selection cancelled.{Color.RESET}")
            sys.exit(0)


# ══════════════════════════════════════════════════════════════════════════════
# ARP SPOOFING DETECTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class ARPSpoofingDetector:
    """
    Core detection engine for ARP spoofing attacks.

    Maintains two data structures:
      - ip_mac_table  : dict mapping IP → MAC (primary trust table)
      - mac_ip_table  : dict mapping MAC → set of IPs (reverse lookup for MAC reuse detection)

    Detection triggers:
      1. MAC Change     : A known IP now claims a different MAC
      2. MAC Reuse      : A single MAC address is claiming ownership of multiple IPs
                          (common when an attacker poisons multiple entries)
    """

    def __init__(self):
        # Primary ARP table: IP address → MAC address
        self.ip_mac_table  = {}
        # Reverse lookup: MAC address → set of IP addresses
        self.mac_ip_table  = defaultdict(set)
        # Alert counter
        self.alert_count   = 0

    def check_and_update(self, ip: str, mac: str) -> bool:
        """
        Checks an IP/MAC pair against the known table and updates it.

        Logic:
          1. If IP is new → add to table, no alert
          2. If IP is known and MAC matches → no alert (normal)
          3. If IP is known but MAC has CHANGED → ALERT (possible spoofing)
          4. If MAC is already used by ANOTHER IP → ALERT (MAC reuse / impersonation)

        Parameters:
            ip  : Sender IP from ARP packet
            mac : Sender MAC from ARP packet

        Returns:
            True if an anomaly was detected, False if normal
        """
        anomaly_detected = False

        # ── Detection Trigger 1: Known IP with a different MAC ──────────────
        if ip in self.ip_mac_table:
            known_mac = self.ip_mac_table[ip]

            if known_mac.lower() != mac.lower():
                # The IP has a NEW MAC — this is the hallmark of ARP poisoning
                self.alert_count += 1
                anomaly_detected = True

                alert_msg = (
                    f"MAC ADDRESS CHANGED for IP {ip}! "
                    f"POSSIBLE ARP SPOOFING / MAN-IN-THE-MIDDLE ATTACK!"
                )

                # Print colorized alert to terminal
                self._print_alert(ip, known_mac, mac, alert_msg)

                # Write to log file
                log_alert(ip, known_mac, mac, alert_msg)

                # Update table with the new MAC (continue monitoring)
                self.ip_mac_table[ip] = mac
                self.mac_ip_table[mac].add(ip)

                return True  # Anomaly found — exit early

        else:
            # ── New IP — add to trust table ──────────────────────────────
            self.ip_mac_table[ip]  = mac
            self.mac_ip_table[mac].add(ip)

        # ── Detection Trigger 2: MAC already maps to a DIFFERENT IP ──────
        # If one physical MAC is claiming multiple distinct IP addresses,
        # this often indicates the attacker is forwarding traffic for multiple victims.
        existing_ips = self.mac_ip_table[mac]
        if len(existing_ips) > 1:
            conflicting_ips = existing_ips - {ip}
            for conflict_ip in conflicting_ips:
                if conflict_ip != ip:
                    self.alert_count += 1
                    anomaly_detected = True
                    alert_msg = (
                        f"MAC {mac} is claiming MULTIPLE IPs: {ip} and {conflict_ip}. "
                        f"Potential ARP impersonation or gateway hijack!"
                    )
                    self._print_alert(ip, conflict_ip, mac, alert_msg)
                    log_alert(ip, f"(was {conflict_ip})", mac, alert_msg)

        return anomaly_detected

    @staticmethod
    def _print_alert(ip: str, old_mac: str, new_mac: str, message: str):
        """
        Prints a visually distinct, colorized alert banner to the terminal.
        """
        print(f"\n{Color.RED}{'!' * 70}{Color.RESET}")
        print(f"{Color.RED}{Color.BOLD}  ⚠  ARP SPOOFING ALERT DETECTED  ⚠{Color.RESET}")
        print(f"{Color.RED}{'!' * 70}{Color.RESET}")
        print(f"  {Color.BOLD}IP Address  :{Color.RESET} {Color.WHITE}{ip}{Color.RESET}")
        print(f"  {Color.BOLD}Old MAC     :{Color.RESET} {Color.GREEN}{old_mac}{Color.RESET}")
        print(f"  {Color.BOLD}New MAC     :{Color.RESET} {Color.RED}{new_mac}{Color.RESET}")
        print(f"  {Color.BOLD}Alert       :{Color.RESET} {Color.YELLOW}{message}{Color.RESET}")
        print(f"  {Color.BOLD}Time        :{Color.RESET} {datetime.now().strftime('%H:%M:%S')}")
        print(f"  {Color.MAGENTA}→ Logged to: {LOG_FILE}{Color.RESET}")
        print(f"{Color.RED}{'!' * 70}{Color.RESET}\n")


# ══════════════════════════════════════════════════════════════════════════════
# PACKET SNIFFING ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class PacketSniffer:
    """
    Real-time packet capture engine using Scapy.

    Responsibilities:
      - Capture packets on the chosen interface
      - Parse and display general packet summaries (IP/TCP/UDP/ICMP)
      - Extract ARP packets and forward them to the ARPSpoofingDetector
      - Count total packets and maintain running statistics
    """

    def __init__(self, interface: str, detector: ARPSpoofingDetector):
        """
        Parameters:
            interface : Network interface name to sniff on
            detector  : ARPSpoofingDetector instance to analyze ARP packets
        """
        self.interface    = interface
        self.detector     = detector
        self.packet_count = 0
        self.arp_count    = 0
        self.start_time   = None

    def process_packet(self, packet):
        """
        Callback invoked by Scapy for every captured packet.
        Wrapped in try/except to prevent crashes on malformed packets.

        Parameters:
            packet : Scapy packet object
        """
        try:
            self.packet_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S")

            # ── ARP Packet Handler ──────────────────────────────────────────
            # ARP op codes:
            #   1 = ARP Request  (who-has)
            #   2 = ARP Reply    (is-at)  ← Primary vector for spoofing
            if packet.haslayer(ARP):
                self._handle_arp_packet(packet, timestamp)

            # ── General IP Packet Summary ───────────────────────────────────
            elif packet.haslayer(IP):
                self._handle_ip_packet(packet, timestamp)

        except Exception as e:
            # Never crash on a single bad packet — log and continue
            print(f"{Color.YELLOW}[WARN] Could not parse packet #{self.packet_count}: {e}{Color.RESET}")

    def _handle_arp_packet(self, packet, timestamp: str):
        """
        Processes ARP packets.
          - Displays ARP summary (request or reply)
          - Extracts sender IP and MAC and passes to detector

        ARP Reply packets (op=2) are the primary vehicle for ARP spoofing.
        We inspect both requests and replies but flag op=2 more prominently.
        """
        self.arp_count += 1
        arp_layer = packet[ARP]

        op_map  = {1: "REQUEST", 2: "REPLY  "}
        op_name = op_map.get(arp_layer.op, f"OP:{arp_layer.op}")

        sender_ip  = arp_layer.psrc   # Protocol (IP) source
        sender_mac = arp_layer.hwsrc  # Hardware (MAC) source
        target_ip  = arp_layer.pdst   # Protocol (IP) destination

        # Color-code ARP replies in yellow (higher interest for detection)
        color = Color.YELLOW if arp_layer.op == 2 else Color.CYAN

        print(
            f"{color}[{timestamp}] ARP {op_name} | "
            f"{sender_ip:>16} ({sender_mac}) → {target_ip}"
            f"{Color.RESET}"
        )

        # Pass ARP reply data to the spoofing detection engine
        # (We monitor requests too in case of gratuitous ARP attacks)
        if arp_layer.op in (1, 2):
            self.detector.check_and_update(sender_ip, sender_mac)

    def _handle_ip_packet(self, packet, timestamp: str):
        """
        Processes regular IP packets and displays a compact one-line summary.
        Identifies protocol type (TCP, UDP, ICMP, or OTHER).
        """
        ip_layer = packet[IP]
        src_ip   = ip_layer.src
        dst_ip   = ip_layer.dst

        if packet.haslayer(TCP):
            proto    = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            detail   = f"ports {src_port} → {dst_port}"
        elif packet.haslayer(UDP):
            proto    = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            detail   = f"ports {src_port} → {dst_port}"
        elif packet.haslayer(ICMP):
            proto  = "ICMP"
            detail = f"type {packet[ICMP].type}"
        else:
            proto  = f"IP/{ip_layer.proto}"
            detail = ""

        print(
            f"{Color.WHITE}[{timestamp}] {proto:<6} | "
            f"{src_ip:>16} → {dst_ip:<16} {detail}{Color.RESET}"
        )

    def start(self):
        """
        Starts packet sniffing on the selected interface.
        Uses Scapy's sniff() function in non-blocking continuous mode.
        The sniff loop runs until interrupted with Ctrl+C (KeyboardInterrupt).
        """
        self.start_time = time.time()

        print(f"{Color.GREEN}{Color.BOLD}")
        print("  ┌─────────────────────────────────────────────────────────┐")
        print(f"  │  Sniffing started on interface: {self.interface:<27}│")
        print("  │  Press Ctrl+C to stop.                                  │")
        print("  └─────────────────────────────────────────────────────────┘")
        print(f"{Color.RESET}")
        print(
            f"  {Color.CYAN}[TIMESTAMP]{Color.RESET} "
            f"{'PROTO':<10} "
            f"{'SOURCE':>20} {'':^5} {'DESTINATION':<20} DETAIL"
        )
        print(f"  {'─' * 80}")

        try:
            # Scapy sniff():
            #   iface  = network interface to listen on
            #   prn    = callback function for each packet
            #   store  = False → don't keep packets in memory (saves RAM)
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False
            )
        except PermissionError:
            print(f"\n{Color.RED}[ERROR] Permission denied — run this script with sudo / administrator privileges.{Color.RESET}")
            sys.exit(1)
        except OSError as e:
            print(f"\n{Color.RED}[ERROR] Interface error: {e}{Color.RESET}")
            sys.exit(1)

    def print_statistics(self):
        """
        Prints a summary of the sniffing session:
          - Duration
          - Total packets captured
          - ARP packets seen
          - Spoofing alerts raised
        """
        elapsed = time.time() - self.start_time if self.start_time else 0
        print(f"\n{Color.BOLD}{Color.CYAN}")
        print("  ╔══════════════════════════════════════════════════════╗")
        print("  ║              SESSION SUMMARY                         ║")
        print("  ╠══════════════════════════════════════════════════════╣")
        print(f"  ║  Duration          : {elapsed:<30.1f}s ║")
        print(f"  ║  Total Packets     : {self.packet_count:<31}║")
        print(f"  ║  ARP Packets       : {self.arp_count:<31}║")
        print(f"  ║  Spoofing Alerts   : {self.detector.alert_count:<31}║")
        print(f"  ║  Log File          : {LOG_FILE:<31}║")
        print("  ╚══════════════════════════════════════════════════════╝")
        print(f"{Color.RESET}")

        # Print current ARP trust table for reference
        if self.detector.ip_mac_table:
            print(f"\n{Color.BOLD}  Final ARP Trust Table:{Color.RESET}")
            print(f"  {'IP Address':<20} {'MAC Address'}")
            print(f"  {'─' * 50}")
            for ip, mac in sorted(self.detector.ip_mac_table.items()):
                print(f"  {ip:<20} {mac}")
        print()

        # Log session end
        log_session_end(self.packet_count, self.detector.alert_count)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    """
    Main execution flow:
      1. Print banner and disclaimer
      2. List available network interfaces
      3. Prompt user to select interface
      4. Initialize logger and detector
      5. Start packet sniffing
      6. On Ctrl+C → print session statistics and exit
    """

    # ── Step 1: Banner ──────────────────────────────────────────────────────
    print(f"{Color.CYAN}{BANNER}{Color.RESET}")

    # ── Ethical Disclaimer ─────────────────────────────────────────────────
    print(f"{Color.RED}{Color.BOLD}  ⚠  ETHICAL USAGE DISCLAIMER  ⚠{Color.RESET}")
    print(f"{Color.RED}  This tool is for EDUCATIONAL and DEFENSIVE use ONLY.")
    print(f"  Use ONLY on networks you OWN or have WRITTEN PERMISSION to monitor.")
    print(f"  Unauthorized packet sniffing is ILLEGAL in most jurisdictions.{Color.RESET}\n")

    # ── Step 2: Privilege check (soft warning) ─────────────────────────────
    if os.name != "nt" and os.geteuid() != 0:
        print(f"{Color.YELLOW}[WARNING] Not running as root. Packet capture may fail.")
        print(f"          Consider re-running with: sudo python3 {sys.argv[0]}{Color.RESET}\n")

    # ── Step 3: Interface selection ────────────────────────────────────────
    interfaces = get_available_interfaces()

    if not interfaces:
        print(f"{Color.RED}[ERROR] No network interfaces found. Exiting.{Color.RESET}")
        sys.exit(1)

    display_interfaces(interfaces)
    selected_iface = select_interface(interfaces)

    # ── Step 4: Initialize logger and detection engine ─────────────────────
    initialize_log()
    print(f"{Color.GREEN}[+] Log file initialized: {LOG_FILE}{Color.RESET}")

    detector = ARPSpoofingDetector()
    sniffer  = PacketSniffer(interface=selected_iface, detector=detector)

    # ── Step 5: Start sniffing ─────────────────────────────────────────────
    try:
        sniffer.start()
    except KeyboardInterrupt:
        pass  # Graceful stop on Ctrl+C

    # ── Step 6: Print final statistics ────────────────────────────────────
    print(f"\n{Color.YELLOW}[!] Sniffing stopped by user.{Color.RESET}")
    sniffer.print_statistics()
    print(f"{Color.GREEN}[✓] Session complete. Review '{LOG_FILE}' for logged alerts.{Color.RESET}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Script entry guard
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
