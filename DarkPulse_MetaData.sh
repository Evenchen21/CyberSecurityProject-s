#!/bin/bash
## Tool to get the Domain/site files and metadata By Guy Evenchen ##


# Copyright © Guy_Evenchen 2023-2024

#All rights reserved. This script is the intellectual property of Guy Evenchen. You may use, modify, and distribute this script for educational and non-commercial purposes only. Any unauthorized use, reproduction, or distribution is strictly prohibited. [Your Name] assumes no responsibility for any damages or liabilities arising from the use of this script.

# For inquiries, please contact https://www.linkedin.com/in/guy-evenchen/ .




##Dont Touch##

HOME=$(pwd)
DIRECTORY=$HOME/Wgetfolder
IP=$(curl ifconfig.me)
COUNTRY=$(geoiplookup $IP | awk '{print$4}'| sed 's/,/ /g')





function Exiftool() {
	sudo exiftool "/home/kali/Desktop/Wgetfolder/Results_Wget_$DomainName" > "Result_$DomainName.txt"
	
	echo "Saved the MetaData and downloaded files for the entered Domain: $DomainNames .."
	sleep 2
	sudo perl nipe.pl stop
	exit
}

function ScanningAnonymous() {
	echo "Please Enter the Full Domain Name:"
	read DomainName
	echo "Scanning and Downloading Files from: $DomainName.." 
	sleep 2
	sudo wget "$DomainName" --user-agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0" -N -r -nd -P "/home/kali/Desktop/Wgetfolder" --level=1 -e robots=off -A jpg,gif,exe,txt,zip,png,index,tmp -H > "Results_$DomainName"
	
	Exiftool
}

function RunNipe() {
	echo "Running Nipe..."
	sleep 2
	cd $DIRECTORY/nipe
	sudo perl nipe.pl restart
	sudo perl nipe.pl status
	sudo perl nipe.pl restart
	sudo perl nipe.pl status
	
	if [ "$COUNTRY" == "IL" ]
		then
		echo "$(whoami) is not anonymous.. exiting tool!"
		sleep 2
		exit
	else
		echo "$(whoami) is indeed anonymous!"
		ScanningAnonymous
	fi
}

function InstallNipe() {
	cd "/home/kali/Desktop/Wgetfolder"
	echo "Installing GeoIPLookUP.."
	sudo apt install geoip-bin -y > /dev/null 2>&1
	echo "Installing Nipe Tool..."
	git clone https://github.com/htrgouvea/nipe.git > /dev/null 2>&1
	sudo cpan install Try::Tiny Config::Simple JSON > /dev/null 2>&1
	sudo perl nipe.pl install > /dev/null 2>&1
	cd nipe
	echo "Installation Done!"
	sleep 3
	
	RunNipe
}

## Checking if DIR found ##

function CheckDirectory() {
	if [ -d "$DIRECTORY" ]
	then
		echo "All OK, running Nipe.."
		RunNipe
	else
		echo "Installing Tool's.."
		InstallNipe
	fi
}

## Starting Wget Script ##
function WGetscriptStart() {
	echo "~~~~~~~~~~ Running Wget Script ~~~~~~~~~~"
	
	if [ -d "$DIRECTORY" ]
	then
		CheckDirectory
	else
		echo "Making WgetFolder.."
		sudo mkdir "$DIRECTORY/Wget_Results"
		CheckDirectory
	fi
}

WGetscriptStart
