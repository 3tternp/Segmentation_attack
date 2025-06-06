from scapy.all import IP, ICMP, send
import sys

def ip_spoof(target_ip, spoofed_ip):
    packet = IP(dst=target_ip, src=spoofed_ip)/ICMP()
    send(packet, count=5, verbose=True)
    return f"Sent 5 ICMP packets to {target_ip} spoofed as {spoofed_ip}"

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.10'
    spoof = sys.argv[2] if len(sys.argv) > 2 else '1.2.3.4'
    print(ip_spoof(target, spoof))
