#!/usr/bin/env python3
import socket
import struct
import argparse
import sys
import textwrap

# Return properly formatted MAC address (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    # Removed socket.htons() — EtherType is already in network byte order
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), proto, data[14:]

# Small helper to map common ethertypes
def ethertype_name(proto):
    return {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
    }.get(proto, f"Unknown (0x{proto:04x})")
    
# Unpack IPv4
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4 #bit shift 4 to the right
    header_length = (version_header_length & 15) * 4 #length of header (end) determines where content 
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]
    
def ipv4(addr):
    return '.'.join(map(str, addr))
    
# Unpack ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP 
def tcp_segment(data):
    (src_port, dest_port, seq, ack, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 16) >> 4
    flag_psh = (offset_reserved_flag & 8) >> 3
    flag_rst = (offset_reserved_flag & 4) >> 2
    flag_syn = (offset_reserved_flag & 2) >> 1
    flag_fin = offset_reserved_flag & 1
    return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

    
# Unpack UDP
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def main(interface):
    try:
        # AF_PACKET + SOCK_RAW is Linux-specific; requires root or cap_net_raw
        con = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        con.bind((interface, 0))
    except PermissionError:
        print("Permission denied: raw sockets require root privileges.")
        sys.exit(1)
    except OSError as e:
        print(f"OS error creating raw socket: {e}")
        sys.exit(1)

    print(f"Listening on interface: {interface} (ctrl-c to stop)")

    try:
        while True:
            raw_data, addr = con.recvfrom(65536)
            dest_mac, src_mac, eth_proto, payload = ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print(f'  Dest: {dest_mac}, Src: {src_mac}, Proto: {ethertype_name(eth_proto)}')

            # IPv4
            if eth_proto == 0x0800:
                version, header_length, ttl, proto, src, target, data = ipv4_packet(payload)
                print('  IPv4 Packet:')
                print(f'    Version: {version}, Header Length: {header_length}, TTL: {ttl}')
                print(f'    Source: {src}, Target: {target}, Protocol: {proto}')

                # ICMP
                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print('    ICMP Packet:')
                    print(f'      Type: {icmp_type}, Code: {code}, Checksum: {checksum}')

                # TCP
                elif proto == 6:
                    src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                    print('    TCP Segment:')
                    print(f'      Src Port: {src_port}, Dest Port: {dest_port}')
                    print(f'      Seq: {seq}, Ack: {ack}')
                    print(f'      Flags: URG={flag_urg}, ACK={flag_ack}, PSH={flag_psh}, RST={flag_rst}, SYN={flag_syn}, FIN={flag_fin}')

                # UDP
                elif proto == 17:
                    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
                    print('    UDP Segment:')
                    print(f'      Src Port: {src_port}, Dest Port: {dest_port}, Length: {size}')

    except KeyboardInterrupt:
        print("\nStopping sniffer.")
    finally:
        con.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Ethernet sniffer (Linux only).")
    parser.add_argument('-i', '--interface', default='eth0', help='Interface to listen on (default: eth0)')
    args = parser.parse_args()
    main(args.interface)

