#!/bin/bash

### Dont Touch ###
HOME=$(pwd)
TOOL=$HOME/Volatility_Results_Folder

## GUY EVENCHEN Volatility / Memory / HDD Analysis Tool ##

# Copyright © Guy_Evenchen 2023

#All rights reserved. This script is the intellectual property of Guy Evenchen. You may use, modify, and distribute this script for educational and non-commercial purposes only. Any unauthorized use, reproduction, or distribution is strictly prohibited. [Your Name] assumes no responsibility for any damages or liabilities arising from the use of this script.

# For inquiries, please contact https://www.linkedin.com/in/guy-evenchen/ .




function ResultsOfAnalysis()
{
zip -r AnalysisFolder.zip $HOME/Volatility_Results_Folder
	
	
echo "Done"
sleep 2
exit
}





function AnalysisVolatility()

{
	
echo "[!] Analyzing the Dump file: $NAME"
sleep 1
echo "[!] Starting Analyzing with Volatility [!]"
PROFILE=$(./volatility_2.6_lin64_standalone -f "$NAME" imageinfo | grep win | awk -F '.' '{print$1}' | awk -F ':' '{print$2}' | sed 's/ //g' ) > SCANPROFILE.txt
echo "[!] Investigated system profile: $PROFILE [!]" 
PLUGINS="pstree connscan pslist hivelist printkey"
echo "[!] Extracting Informaion..[!]"
for p in $PLUGINS
	do
		echo "[!] Plugin Being Used: $p"
		$(./volatility_2.6_lin64_standalone -f "$NAME" --profile=PROFILE $p > "$TOOL/$NAME/$res_$p.txt" 2> /dev/null) VolatilityResultFile="$TOOL/$NAME/$res_$p.txt"
	done
	
	echo "[!] Analysis Results were saved to a file inside the Directory "
	ResultsOfAnalysis	
}



function AnalysisTools[]
{
echo "[!] Analyzing file [!]"
sleep 1
echo "[!] Analyzing via BinWalk [!]"
$(binwalk "$FullPathFile" >> "Analysis_BinWalk_$basename.txt" && ls -l | wc -l) BinwalkResultFile="Analysis_BinWalk_$basename.txt"
echo "[!] Analyzing via Foremost [!]"
$(foremost "$FullPathFile" -o "Analysis_Foremost_$basename" && ls -l | wc -l)  ForemostResultFile="Analysis_Foremost_$basename"
echo "[!] Analyzing via Bulk_Extractor [!]"
$(bulk_extractor "$FullPathFile" -o "Analysis_BulkExtractor_$basename" && ls -l | wc -l > PcapFile) BulkExtractorResultFile="Analysis_BulkExtractor_$basename"
	if [-f packets.pcap ]
	then
		echo "[!] Network file was found! [!]"
		stat -c "%sK" $PcapFile
		
		AnalysisVolatility
		
	fi 
}


function InstallVolatility()
{
mkdir -p $TOOL/$NAME > /dev/null 2>&1
cd $TOOL
wget http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip 2>&1
echo "[!] Volatility Tool was downloaded to the path $TOOL [!] .."
unzip volatility_2.6_lin64_standalone.zip 2>&1
echo "[+] Installing Bulk_Extractor..[+]"
apt-get install bulk-extractor 2>&1
echo "[+] Installing BinWalk..[+]"
apt-get install binwalk 2>&1
echo "[+] Installing Foremost.. [+]"
apt-get install foremost 2>&1
echo "[!] Done [!]"

AnalysisTools
}




function StartAnalysis()

{
	echo " [!] Please Enter the Full path to your memory (.mem) / HardDrive file: "
	read FullPathFile
	NAME=$(basename $FullPathFile) 2>&1
	
	if [ -d $TOOL]
	then 
		AnalysisTools
		
	else
		InstallVolatility
	fi
}


function CheckingRootPrivileges()
{
	if [ "$(id -u)" != "0" ] 
	then
		echo "[X] This script must be run as root user!"
        echo "[X] Existing Script.."
        exit 3
        
	else
		StartAnalysis 
        
	fi
}

CheckingRootPrivileges
