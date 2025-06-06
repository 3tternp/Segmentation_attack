# main.py
import subprocess
from tabulate import tabulate
import os
import datetime
from docx import Document
from docx.shared import Inches


def run_script(script_name, args=[]):
    script_path = os.path.join("core", script_name)
    try:
        result = subprocess.run(['python3', script_path] + args, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error running {script_name}: {str(e)}"


layer2_attacks = {
    "1": ("arp_poisoning.py", "ARP Poisoning Attack"),
    "2": ("dns_poisoning.py", "DNS Cache Poisoning Attack"),
    "3": ("cdp_flooding.py", "CDP Flooding Attack"),
    "4": ("mac_flooding.py", "MAC Flooding Attack"),
    "5": ("stp_root_guard.py", "STP Root Guard Attack"),
    "6": ("dhcp_flooding.py", "DHCP Flooding Attack"),
    "7": ("dtp_attack.py", "DTP Attack")
}

layer3_attacks = {
    "1": ("ip_spoofing.py", "IP Spoofing Attack"),
    "2": ("icmp_flood.py", "ICMP Flood Attack"),
    "3": ("udp_flood.py", "UDP Flood Attack"),
    "4": ("tcp_syn_flood.py", "TCP SYN Flood Attack")
}


def save_report_to_docx(headers, data, filename):
    doc = Document()
    doc.add_heading("Segmentation Testing Report", 0)

    table = doc.add_table(rows=1, cols=len(headers))
    hdr_cells = table.rows[0].cells
    for i, header in enumerate(headers):
        hdr_cells[i].text = header

    for row in data:
        row_cells = table.add_row().cells
        for i, item in enumerate(row):
            row_cells[i].text = str(item)

    doc.save(filename)


def main():
    print("Select the attack layer:")
    print("1. Layer 2 Attacks")
    print("2. Layer 3 Attacks")
    layer_choice = input("Enter 1 or 2: ").strip()

    if layer_choice == "1":
        selected_attacks = layer2_attacks
        layer_type = "Layer 2 manipulation"
    elif layer_choice == "2":
        selected_attacks = layer3_attacks
        layer_type = "Layer 3 manipulation"
    else:
        print("Invalid choice.")
        return

    print("\nSelect the attack to run:")
    for key, (_, desc) in selected_attacks.items():
        print(f"{key}. {desc}")

    choice = input("Enter the number of the attack: ").strip()
    target_ip = input("Enter target IP address (if applicable): ").strip()

    if choice in selected_attacks:
        script_name, issue = selected_attacks[choice]
        output = run_script(script_name, [target_ip])

        report_data = [[
            issue,
            target_ip,
            "Scapy/Custom",
            "N/A",
            layer_type,
            "Low to Medium",
            "Low",
            "None",
            "Local",
            "Partial",
            "Partial",
            "Partial",
            "Medium",
            "Possible lateral movement, traffic capture",
            "Use segmentation, filtering, and monitoring",
            output
        ]]

        headers = [
            "Issue Name", "Targeted IP", "Method used", "Port Used", "Vulnerability details",
            "Attack Vector", "Attack Complexity", "Privileges Required", "User Interaction",
            "Scope", "Confidentiality", "Integrity", "Availability", "Severity-Rating",
            "Business impact", "Remediation", "Proof of Concept"
        ]

        print("\n=== Attack Report ===")
        print(tabulate(report_data, headers=headers, tablefmt="grid"))

        os.makedirs("output", exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        docx_filename = os.path.join("output", f"segmentation_report_{timestamp}.docx")
        save_report_to_docx(headers, report_data, docx_filename)
        print(f"\n[+] Report saved to: {docx_filename}")

    else:
        print("Invalid choice.")


if __name__ == '__main__':
    main()
