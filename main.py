# main.py
import subprocess
from tabulate import tabulate

def run_script(script_name, args=[]):
    try:
        result = subprocess.run(['python3', script_name] + args, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error running {script_name}: {str(e)}"

attack_scripts = {
    "1": ("arp_poisoning.py", "ARP Poisoning Attack"),
    "2": ("dns_poisoning.py", "DNS Cache Poisoning Attack"),
    "3": ("cdp_flooding.py", "CDP Flooding Attack"),
    "4": ("mac_flooding.py", "MAC Flooding Attack"),
    "5": ("stp_root_guard.py", "STP Root Guard Attack"),
    "6": ("dhcp_flooding.py", "DHCP Flooding Attack"),
    "7": ("dtp_attack.py", "DTP Attack")
}

def main():
    print("Select the attack to run:")
    for key, (_, desc) in attack_scripts.items():
        print(f"{key}. {desc}")

    choice = input("Enter the number of the attack: ").strip()
    target_ip = input("Enter target IP address (if applicable): ").strip()

    if choice in attack_scripts:
        script_name, issue = attack_scripts[choice]
        output = run_script(script_name, [target_ip])

        # Dummy static report format for now (can be enhanced to parse output)
        report_data = [[
            issue,
            target_ip,
            "Scapy/Custom",
            "N/A",
            "Layer 2 manipulation",
            "Low to Medium",
            "Low",
            "None",
            "Local",
            "Partial",
            "Partial",
            "Partial",
            "Medium",
            "Possible lateral movement, traffic capture",
            "Use static ARP, enable dynamic ARP inspection",
            output
        ]]

        headers = ["Issue Name", "Targeted IP", "Method used", "Port Used", "Vulnerability details",
                   "Attack Vector", "Attack Complexity", "Privileges Required", "User Interaction",
                   "Scope", "Confidentiality", "Integrity", "Availability", "Severity-Rating",
                   "Business impact", "Remediation", "Proof of Concept"]

        print("\n=== Attack Report ===")
        print(tabulate(report_data, headers=headers, tablefmt="grid"))
    else:
        print("Invalid choice.")

if __name__ == '__main__':
    main()
