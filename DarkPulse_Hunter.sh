#!/bin/bash

### Guy Evenchen Network Analysis - Hunter script 4 ###



# Copyright © Guy_Evenchen 2023

#All rights reserved. This script is the intellectual property of Guy Evenchen. You may use, modify, and distribute this script for educational and non-commercial purposes only. Any unauthorized use, reproduction, or distribution is strictly prohibited. [Your Name] assumes no responsibility for any damages or liabilities arising from the use of this script.

# For inquiries, please contact https://www.linkedin.com/in/guy-evenchen/ .



## Paths - DO NOT Touch ##
#####################################################################
LOCATION=$(pwd)                                                    
INTERFACE=eth0                                                      
CUSTOM_PATH="/home/kali/Desktop"                                      
OUTPUT_PATH="/home/kali/Desktop/Hunter_File"                        
EXPORT_PATH="/home/kali/Desktop/Hunter_Export"                      
TSHARK_FILTER1="frame.len < 1024000"                                
TSHARK_FILTER2="tcp.segment_data"                                   
#####################################################################




##After sniffing the network,the T-Shark is reading the pcap file and starting exporting files and alerting if there is any Malicious file or IP found.##
## The script is showing the Malicious file and showing the md5 hash and saving it into a file ##

function trap_ctrlc() {
    tshark -r "$OUTPUT_PATH" -Y "$TSHARK_FILTER1" -Y "$TSHARK_FILTER2" --export-objects "http,smb,ftp,$EXPORT_PATH"
    while read -r line; do
        if [[ "$line" =~ [0-9a-fA-F]{9,} ]]; then
            timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            echo "Alert: Address Longer Than 8 Characters - Potential Malicious: $line"
            echo "Checking for Malicious files ... Please wait.."
            file_data=$(echo "$line" | cut -d ":" -f 2- | xxd -r -p)
            if [ ${#file_data} -lt 1024000 ]; then
                file_hash=$(echo -n "$file_data" | sha256sum | awk '{print $1}')
                echo "$timestamp - File Hash: $file_hash" >> /home/kali/Desktop/Hash_output.txt
            fi
        fi
    done < "$OUTPUT_PATH"
     echo "Analysis Done .. Bye :)"
     exit 
}

trap "trap_ctrlc" 2

## Script Starts Here ##
## Script is showing the Local IP Address and starting the local network scan via T-Shark,after the user pressing Ctrl + C the analysis on the pcap file ## 
echo "$(figlet "Hunter - GE")"
sleep 1
echo "Current Location is: $LOCATION"
sleep 1
echo "[*] Exported files and Hashes will be stored in: $CUSTOM_PATH "
sleep 1
echo "[*] Starting Analysis with network interface - $INTERFACE"
sleep 1
echo "[*] Your IP Address is => $(ifconfig | awk '/inet /{print $2}' | head -n 1)"
sudo apt-get -y install tshark > /dev/null 2>&1
echo "[*] Starting T-Shark..."
tshark -i $INTERFACE -f "tcp port 80" -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri -w $OUTPUT_PATH  > /dev/null 1>&1

read -p "Hey Hunter, Pcap captured! Press Ctrl+C once to start analysis on your network... " ANS

sleep 100
