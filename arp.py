from scapy.all import sniff, ARP, Ether
from datetime import datetime


ip_mac_map = {}

def process_packet(packet):
    
    if packet.haslayer(ARP) and packet.haslayer(Ether):

        src_ip = packet[ARP].psrc
        src_mac = packet[Ether].src

       
        if src_mac in ip_mac_map:
            if ip_mac_map[src_mac] != src_ip:
                print("\n[!] POSSIBLE ARP SPOOFING DETECTED!")
                print(f"    Time: {datetime.now()}")
                print(f"    MAC address: {src_mac}")
                print(f"    Old IP: {ip_mac_map[src_mac]}")
                print(f"    New IP: {src_ip}")
                print("    This MAC is pretending to be another IP!\n")
        else:
         
            ip_mac_map[src_mac] = src_ip


print("[*] ARP detector started...")
print("[*] Listening for ARP packets...\n")

sniff(
    filter="arp",
    store=False,
    prn=process_packet
)
