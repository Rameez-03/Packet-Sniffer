# README — Packet Sniffer (sniffer.py / sniffer_scap.py)

This README explains how to run the sniffers end-to-end (live capture → save to PCAP on Windows), how to generate simple test traffic to observe, and quick troubleshooting steps.

---

## 📁 Files in this folder

- `sniffer.py` — raw-socket sniffer for **Linux** (prints parsed Ethernet/IP/TCP/UDP/ICMP to console)  
- `sniffer_scap.py` — **Scapy**-based sniffer for **Windows** (prints live summaries and saves to a `.pcap` file)  

---

## Quick test (minimum steps)

1. **Start the Sniffer** :

   ```powershell
   python .\sniffer.py
   ```
   ```powershell
   python .\sniffer_scap.py
   ```

### 🪟 Windows (Scapy + Npcap)

1. **Open PowerShell as Administrator.**

2. **Install prerequisites:**
   ```powershell
   pip install scapy
