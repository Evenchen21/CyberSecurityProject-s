#!/bin/bash


#### GUY EVENCHEN  HoneyPotScriptProject - ALERTER ####



# Copyright © Guy_Evenchen 2023

#All rights reserved. This script is the intellectual property of Guy Evenchen. You may use, modify, and distribute this script for educational and non-commercial purposes only. Any unauthorized use, reproduction, or  distribution is strictly prohibited. [Your Name] assumes no responsibility for any damages or liabilities arising from the use of this script.

# For inquiries, please contact https://www.linkedin.com/in/guy-evenchen/ .




function Default(){

#### SETTINGS DO NOT TOUCH ####

FILE_SMB_CONF="/etc/samba/smb.conf"
FILE_FTP_CONF="/var/log/vsftpd.log"
FILE_SSH_CONF="/var/log/auth.log"
SSH_DEAULT_PORT="22"

echo "$(figlet Default)"

cd $FILE_SSH_CONF
sed -i "s/^Port .*/Port $SSH_DEAULT_PORT/" /etc/ssh/sshd_config
service ssh restart
echo "[!] SSH BACK TO DEAULT [!]"

cd $FILE_FTP_CONF
sed -i 's/^anonymous_enable=YES/anonymous_enable=NO/' "$FILE_FTP_CONF"

echo "[!] FTP BACK TO DEAULT [!]"

cd $FILE_SMB_CONF

sed -i '/client min protocol = SMB1/d; /client max protocol = SMB1/d' "$FILE_SMB_CONF"

echo "[!] SMB BACK TO DEAULT [!]"
Sleep 1
echo "[!] Done,going back to Menu [!]"
sleep 2

MENU   
}


################################################################################


function ALL(){
#### SETTINGS DO NOT TOUCH ####

FILE_SMB_CONF="/etc/samba/smb.conf"
LOG_SMB="/var/log/samba/log.smbd"
SAVEDLOG_SMB="/home/kali/Desktop/suspicious_ip_addresses_smb.txt"
####
FILE_FTP_CONF="/var/log/vsftpd.log"
LOG_FTP="/home/kali/Desktop/suspicious_ip_addresses_ftp.txt"
####
FILE_SSH_CONF="/var/log/auth.log"
LOG_SSH="/home/kali/Desktop/suspicious_ip_addresses_ssh.txt"
NEW_PORT=$PORTNUMBER


#################################################


echo "$(figlet All)"
sleep 1
echo "[+]------ STARTING WITH SSH  -----[+]"

apt-get install openssh-server > /dev/null 2>&1
service ssh start > /dev/null 2>&1
read -p "Enter the new SSH port number:" PORTNUMBER
echo "Enabling port $NEW_PORT for SSH in $FILE_SSH_CONF"

for CONFIG_FILE in "$LOCATION"*.conf; do
    if [ -f "$CONFIG_FILE" ] && [ -r "$CONFIG_FILE" ]; then
        echo "Modifying Port: $CONFIG_FILE"
        sed -i -E "s/^#?Port[[:space:]]+[0-9]+/Port $NEW_PORT/" "$CONFIG_FILE"
        service ssh restart > /dev/null 2>&1
    else
        echo "Error: Unable to read or find file: $CONFIG_FILE"
    fi
done

IP_ADDRESS=$(date +"%Y-%m-%d %T" | grep sshd $FILE_SSH_CONF | awk '{print $11 $10 $9}' | sort -u) >> $LOG_SSH
echo "Suspicious IP addresses from SSH logs:"
echo "$IP_ADDRESS"


while IFS= read -r $LOG_SSH; do
    echo "Whois information for IP: $ip_address"
    whois "$ip_address" | head -36 | tail -8
    echo "-------------------------------------"
done < "$LOG_SSH"


#x#x#x#x#x#x#x#x#x#x#x#x#x#x#

sleep 3

echo "[+]----- NOW WITH FTP  ------[+]"
sleep 1

sudo apt-get install vsftpd -y > /dev/null 2>&1
sudo service vsftpd restart    > /dev/null 2>&1
sudo sed -i 's/^anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf > /dev/null 2>&1
echo "[!] Enabling 🄰🄽🄾🄽🅈🄼🄾🅄🅂  User [!]"
sleep 1
echo "[*] Monitoring the ftp Service,waiting for bait ( ͡❛ ͜ʖ ͡❛)✊[*]"
if [ ! -f "$FILE_FTP_CONF" ]; then
    echo "Error! - vsftpd log file is not found: $FILE_FTP_CONF"
fi
tail -n 0 -f "$FILE" | while read -r line; do
    if [[ "$LINE" =~ (FAIL|OK)\ LOGIN ]]; then

        IP_ADDRESS=$(echo "$LINE" | awk '{print $6}')
        echo "[!] Suspicious IP address found: [!] $IP_ADDRESS"
        echo "$IP_ADDRESS" >> "$LOG_FTP"
    fi
done


while IFS= read -r $LOG_FTP; do
    echo "Whois information for IP: $ip_address"
    whois "$ip_address" | head -36 | tail -8
    echo "-------------------------------------"
done < "$LOG_FTP"


#x#x#x#x#x#x#x#x#x#x#x#x#x#x#

sleep 3

echo "[+]----- NOW WITH SMB ------[+]"
sleep 1

echo "$(figlet SMB)"
sudo apt-get install samba > /dev/null 2>&1
sudo service smbd restart > /dev/null 2>&1

echo "[*] Starting SMB Protocol Version SMB1 [*]"

LINES_TO_ADD="[global]
client min protocol = SMB1
client max protocol = SMB1"

sudo service smbd restart > /dev/null 2>&1

echo $FILE_SMB_CONF | sudo tee -a $FILE_SMB_CONF

echo "[!] Showing the IP Address that may be bad: [!]"
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /var/log/samba/log.smbd | sort -u > $SAVEDLOG_SMB



while IFS= read -r $SAVEDLOG_SMB; do
    echo "Whois information for IP: $ip_address"
    whois "$ip_address" | head -36 | tail -8
    echo "-------------------------------------"
done < "$SAVEDLOG_SMB"


echo "[!] Done [!]"

MENU
}



################################################################################


function SMB(){
FILE="/etc/samba/smb.conf"
LOG="/var/log/samba/log.smbd"
SAVEDLOG= "/home/kali/Desktop/suspicious_ip_addresses_smb.txt"

echo "$(figlet SMB)"
sudo apt-get install samba > /dev/null 2>&1
sudo service smbd restart > /dev/null 2>&1

echo "[*] Starting SMB Protocol Version SMB1 [*]"

LINES_TO_ADD="[global]
client min protocol = SMB1
client max protocol = SMB1"

sudo service smbd restart > /dev/null 2>&1

echo $FILE | sudo tee -a $FILE

echo "[!] Showing the IP Address that may be bad: [!]"
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /var/log/samba/log.smbd | sort -u > $SAVEDLOG


MENU

}



################################################################################

function FTP(){
FILE="/var/log/vsftpd.log"
LOG="/home/kali/Desktop/suspicious_ip_addresses_ftp.txt"

echo "$(figlet FTP)"
sudo apt-get install vsftpd -y > /dev/null 2>&1
sudo service vsftpd restart    > /dev/null 2>&1
sudo sed -i 's/^anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf > /dev/null 2>&1
echo "[!] Enabling 🄰🄽🄾🄽🅈🄼🄾🅄🅂  User [!]"
sleep 1
echo "[*] Monitoring the ftp Service,waiting for bait ( ͡❛ ͜ʖ ͡❛)✊[*]"
if [ ! -f "$FILE" ]; then
    echo "Error! - vsftpd log file not found: $FILE"
fi
tail -n 0 -f "$FILE" | while read -r line; do
    if [[ "$LINE" =~ (FAIL|OK)\ LOGIN ]]; then

        IP_ADDRESS=$(echo "$LINE" | awk '{print $6}')
        echo "[!] Suspicious IP address found: [!] $IP_ADDRESS"
        echo "$IP_ADDRESS" >> "$LOG"
    fi
done


MENU
}

################################################################################


function SSH(){

LOCATION="/etc/ssh/sshd_config"
NEW_PORT=$PORTNUMBER

echo "$(figlet SSH)"
apt-get install openssh-server > /dev/null 2>&1
service ssh start > /dev/null 2>&1
read -p "Enter the new SSH port number:" PORTNUMBER
echo "Enabling port $NEW_PORT for SSH in $LOCATION"

for CONFIG_FILE in "$LOCATION"*.conf; do
    if [ -f "$CONFIG_FILE" ] && [ -r "$CONFIG_FILE" ]; then
        echo "Modifying Port: $CONFIG_FILE"
        sed -i -E "s/^#?Port[[:space:]]+[0-9]+/Port $NEW_PORT/" "$CONFIG_FILE"
        service ssh restart > /dev/null 2>&1
    else
        echo "Error: Unable to read or find file: $CONFIG_FILE"
    fi
done

SSH_LOG="/var/log/auth.log"
OUTPUT_FILE="/home/kali/Desktop/suspicious_ip_addresses_ssh.txt"

IP_ADDRESS=$(date +"%Y-%m-%d %T" | grep sshd $SSH_LOG | awk '{print $11 $10 $9}' | sort -u) >> $OUTPUT_FILE
echo "Suspicious IP addresses from SSH logs:"
echo "$IP_ADDRESS"
MENU 
}

################################################################################

function MENU(){
echo "$(figlet ALERTER - GE)"
echo "Guy Evenchen - Project Script v1 ®️"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root/sudo."
    exit
fi

echo "[+] Starting Alerter... [+]"

echo "$(figlet Menu )"

while true; do
    echo "[*] Choose the prefered Services to Monitor: [*]"
    echo "[1] -> SSH "
    echo "[2] -> FTP "
    echo "[3] -> SMB "
    echo "[4] -> All 3 Services "
    echo "[5] -> Reset Ports to Default & Stop all Services 🏴‍☠️"
    echo "[6] -> Exit The Script 💔 "

    read -p "[*] Enter your choice ->" choice

    case $choice in
        1)
            User_Choose "1 - SSH"
            SSH
            ;;
        2)
            User_Choose "2 - FTP"
            FTP
            ;;
        3)
            User_Choose "3 - SMB"
            SMB
            ;;
        4)
            User_Choose "4 - ALL"
            ALL
            ;;

        5)
            User_Choose "5 - Reset & Deault"
            DEFUALT
            ;;
        6)
            echo "[!]Exiting the ALERTER Script.. [!]"
            echo "
██████╗░██╗░░░██╗███████╗
██╔══██╗╚██╗░██╔╝██╔════╝
██████╦╝░╚████╔╝░█████╗░░
██╔══██╗░░╚██╔╝░░██╔══╝░░
██████╦╝░░░██║░░░███████╗
╚═════╝░░░░╚═╝░░░╚══════╝"
            sleep 2
            exit
            exit
            ;;
        *)
            echo "[x] Invalid choice. Please enter a valid option! [x]"
            ;;
    esac
done
}

MENU
