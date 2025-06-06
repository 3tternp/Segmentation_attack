import subprocess
from tabulate import tabulate
import os

def run_script(script_name, args=[]):
    script_path = os.path.join("core", script_name)
    try:
        result = subprocess.run(['python3', script_path] + args, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error running {script_name}: {str(e)}"

layer2_scripts = {
    "1": ("arp_poisoning.py", "ARP Poisoning Attack", ["Target IP"]),
    "2": ("dns_poisoning.py", "DNS Cache Poisoning Attack", ["Target IP"]),
    "3": ("cdp_flooding.py", "CDP Flooding Attack", []),
    "4": ("mac_flooding.py", "MAC Flooding Attack", []),
    "5": ("stp_root_guard.py", "STP Root Guard Attack", []),
    "6": ("dhcp_flooding.py", "DHCP Flooding Attack", []),
    "7": ("dtp_attack.py", "DTP Attack", [])
}

layer3_scripts = {
    "1": ("ip_spoofing.py", "IP Spoofing Attack", ["Target IP", "Spoofed IP"]),
    "2": ("icmp_flood.py", "ICMP Flood Attack", ["Target IP"]),
    "3": ("udp_flood.py", "UDP Flood Attack", ["Target IP", "Target Port"]),
    "4": ("tcp_syn_flood.py", "TCP SYN Flood Attack", ["Target IP", "Target Port"])
}

def get_user_inputs(params):
    inputs = []
    for param in params:
        val = input(f"Enter {param}: ").strip()
        inputs.append(val)
    return inputs

def main():
    print("Select the attack layer:")
    print("1. Layer 2 Attacks")
    print("2. Layer 3 Attacks")
    layer_choice = input("Enter 1 or 2: ").strip()

    if layer_choice == "1":
        scripts = layer2_scripts
    elif layer_choice == "2":
        scripts = layer3_scripts
    else:
        print("Invalid choice")
        return

    print("\nSelect the attack to run:")
    for key, (_, desc, _) in scripts.items():
        print(f"{key}. {desc}")

    choice = input("Enter the number of the attack: ").strip()

    if choice not in scripts:
        print("Invalid attack choice")
        return

    script_name, issue, params = scripts[choice]

    args = get_user_inputs(params)
    output = run_script(script_name, args)

    # Default placeholder report fields - you can customize per attack type
    report_data = [[
        issue,
        args[0] if args else "N/A",
        "Scapy/Custom",
        args[1] if len(args) > 1 else "N/A",
        "Layer {} manipulation".format("2" if layer_choice == "1" else "3"),
        "Low to Medium",
        "Low",
        "None",
        "Local",
        "Partial",
        "Partial",
        "Partial",
        "Medium",
        "Possible lateral movement, traffic capture",
        "Use network segmentation and traffic monitoring",
        output
    ]]

    headers = ["Issue Name", "Targeted IP", "Method used", "Port Used", "Vulnerability details",
               "Attack Vector", "Attack Complexity", "Privileges Required", "User Interaction",
               "Scope", "Confidentiality", "Integrity", "Availability", "Severity-Rating",
               "Business impact", "Remediation", "Proof of Concept"]

    print("\n=== Attack Report ===")
    print(tabulate(report_data, headers=headers, tablefmt="grid"))


if __name__ == '__main__':
    main()
