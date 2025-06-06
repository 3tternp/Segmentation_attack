# Segmentation_attack

Segmentation attacks target weaknesses in network segmentation by bypassing isolation boundaries. Here's a detailed breakdown:

🔹 Layer 2 (Data Link Layer) Segmentation Attacks
Layer 2 attacks often exploit Ethernet or switching technologies, particularly in VLAN-based networks.

1. ARP Poisoning (ARP Spoofing)
Goal: Redirect traffic by spoofing MAC addresses in the ARP table.

Impact: Intercept or alter traffic between hosts (MITM).

Countermeasure: Dynamic ARP Inspection (DAI), static ARP entries.

2. MAC Flooding
Goal: Flood the switch’s MAC table to make it act like a hub.

Impact: Packet sniffing on all ports.

Countermeasure: Port security (limit MAC addresses).

3. VLAN Hopping
Goal: Send tagged frames from a non-trunk port to access other VLANs.

Impact: Unauthorized VLAN access.

Countermeasure: Disable unused ports, force access mode, disable DTP.

4. DTP Attack (Dynamic Trunking Protocol)
Goal: Negotiate a trunk link to gain access to multiple VLANs.

Impact: VLAN segmentation bypass.

Countermeasure: Disable DTP on all access ports.

5. STP Manipulation (Root Guard Bypass)
Goal: Become root bridge by sending spoofed BPDU packets.

Impact: Control switch paths or create loops.

Countermeasure: Root Guard, BPDU Guard.

6. CDP/LLDP Flooding
Goal: Overwhelm the switch with discovery packets.

Impact: Resource exhaustion, potential DoS.

Countermeasure: Disable CDP/LLDP on untrusted ports.

7. DHCP Spoofing/Flooding
Goal: Overwhelm or spoof DHCP to assign malicious configurations.

Impact: Redirect traffic, deny legitimate leases.

Countermeasure: DHCP Snooping.

🔸 Layer 3 (Network Layer) Segmentation Attacks
Layer 3 attacks exploit routing and IP-based segmentation.

1. IP Spoofing
Goal: Send packets with a forged IP to bypass ACLs or impersonate.

Impact: Unauthorized access, MITM.

Countermeasure: Reverse Path Filtering, ingress/egress filtering.

2. ICMP Flood
Goal: Overload the target with ICMP Echo (Ping) requests.

Impact: DoS attack.

Countermeasure: Rate-limiting, firewall rules.

3. TCP SYN Flood
Goal: Send SYN packets without completing the handshake.

Impact: Exhaust server resources.

Countermeasure: SYN cookies, firewalls.

4. UDP Flood
Goal: Send large volumes of UDP packets to random ports.

Impact: Resource consumption and potential DoS.

Countermeasure: Rate-limiting, connection tracking.

📋 Summary
Layer	Attack Type	Primary Objective	Typical Defense
L2	ARP/MAC/DTP/VLAN attacks	Bypass switching & VLAN boundaries	Port security, ACLs, DAI, disable DTP
L3	IP/ICMP/TCP/UDP spoofing	Evade routing rules & overload	Packet filtering, firewalls, anti-DoS tools
