#!/usr/bin/env python3
import os
import sys
import signal
from datetime import datetime
from scapy.all import sniff, PcapWriter
from scapy.arch.windows import get_windows_if_list

# --- Fix Windows environment issues ---
os.environ["SystemRoot"] = "C:\\Windows"
os.environ["SCAPY_CACHE_DIR"] = os.path.join(os.getcwd(), "cache")
os.makedirs(os.environ["SCAPY_CACHE_DIR"], exist_ok=True)

# --- Choose interface automatically or by name ---
def choose_iface(name_hint=None):
    ifaces = get_windows_if_list()
    if not ifaces:
        print("No interfaces found.")
        sys.exit(1)
    if name_hint:
        for i in ifaces:
            if name_hint.lower() in i["name"].lower():
                return i["name"]
    # fallback: first non-loopback
    for i in ifaces:
        if "Loopback" not in i["name"]:
            return i["name"]
    return ifaces[0]["name"]

iface = choose_iface("Wi-Fi")  # change to "Ethernet" if you prefer

# --- Setup output file ---
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
outfile = f"capture_{timestamp}.pcap"
writer = PcapWriter(outfile, append=True, sync=True)

print(f"[+] Capturing on interface: {iface}")
print(f"[+] Writing packets to: {outfile}")
print("[+] Press Ctrl+C to stop.\n")

# --- Function called for each packet ---
def handle_packet(pkt):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {pkt.summary()}")
    writer.write(pkt)

# --- Graceful stop ---
def stop_capture(sig, frame):
    print("\n[!] Stopping capture...")
    writer.close()
    sys.exit(0)

signal.signal(signal.SIGINT, stop_capture)

# --- Start sniffing (no packet limit) ---
sniff(iface=iface, prn=handle_packet, store=False)
