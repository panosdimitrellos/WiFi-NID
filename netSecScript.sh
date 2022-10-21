#! /bin/bash

echo -e "Welcome to NetSec-Analyzer.\n"


#pcap_file=$1

LRED="\e[91m"
GREEN=$'\e[32m'
ENDCOLOR="\e[0m"

Deauthentication(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e  "${LRED}Full report of Deauthentication Frames:\n${ENDCOLOR}"
    echo "frame.number      wlan.sa               wlan.da                         frame.time"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 12)' -n -t ad -T fields -e frame.number -e wlan.sa -e wlan.da -e frame.time
    echo -e "${LRED}\nDeauthentication frames statistics:\n${ENDCOLOR}"
    echo "Packets      Source            Destination"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 12)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    submenu
}

Disassociation(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of Disassociation Frames:\n${ENDCOLOR}"
    echo "frame.number      wlan.sa               wlan.da                         frame.time"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 10)' -n -t ad -T fields -e frame.number -e wlan.sa -e wlan.da -e frame.time
    echo -e "${LRED}\nDisassociation frames statistics:\n${ENDCOLOR}"
    echo "Packets      Source            Destination"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 10)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    submenu
}

Authentication(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of Authentication Frames:\n${ENDCOLOR}"
    echo "frame.number      wlan.sa               wlan.da                         frame.time"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 11)' -n -t ad -T fields -e frame.number -e wlan.sa -e wlan.da -e frame.time
    echo -e "${LRED}\nAuthentication frames statistics:\n${ENDCOLOR}"
    echo "Packets      Source            Destination"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 11)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    submenu
}

BeaconFlood(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Fake Ap Beacon Flood statistics:\n${ENDCOLOR}"
    echo "Packets    MAC address           SSID"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 8) && (frame.len < 150) ' -n | awk --field-separator ' ' '{ print $3 " " $14}' | sort | uniq --count
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    submenu
}

StealthScan(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of TCP SYN Scan Technique${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst     tcp.srcport tcp.dstport         frame.time"
    tshark -r $pcap_file -Y '(tcp.window_size_value <= 1024 and tcp.hdr_len == 24 and tcp.flags == 0x002)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time
    echo -e "\n${LRED}TCP SYN Scan Technique statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '(tcp.window_size_value <= 1024 and tcp.hdr_len == 24 and tcp.flags == 0x002)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    submenu
}


XmassScan(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of TCP Xmass Scan Technique${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst     tcp.srcport tcp.dstport         frame.time"
    tshark -r $pcap_file -Y '((tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1) && (tcp.window_size_value == 1024)) && (tcp.hdr_len == 20)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time
    echo -e "${LRED}\nTCP Xmass Scan Technique statistics:\n${ENDCOLOR}"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '((tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1) && (tcp.window_size_value == 1024)) && (tcp.hdr_len == 20)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    submenu
}


Quit(){
	echo "Exiting script..."
    exit
}

Capture(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    read -p "Enter for how long you want to capture traffic(in seconds): " seconds 
    echo -e "Starting capturing traffic...\n"
    tshark -i any -a duration:$seconds -w captureNetsec 
    pcap_file=captureNetsec
    echo -e "Capture stopped.\n"
    echo -e "Analyze catpured file: ${GREEN}$pcap_file${ENDCOLOR} \n"
    submenu
}

Analyze(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    read -p "Enter the file you want to analyze. (It has to be in the same directory): " pcap_file
    echo -e "Analyze catpured file: ${GREEN}$pcap_file${ENDCOLOR} \n"
    submenu
}

#submenu
submenu(){
    echo -e "Select the information security concerns you would like to check:\n"
    local PS3="Enter an option: "
    local options=(
        "Scan for Deauthentication attack(aireplay-ng, mdk3, mdk4)" 
        "Scan for Disassociation attack(mdk3, mdk4)" 
        "Scan for Authentication DoS(mdk3, mdk4)" 
        "Scan for Fake AP beacon flood(mdk3, mdk4)"
        "Scan for TCP SYN Scan/Stealth Scan(nmap)"
        "Scan for TCP Xmass Scan(nmap)"
        "Back")
    local opt
    select opt in "${options[@]}"
    do
        case $opt in
            "Scan for Deauthentication attack(aireplay-ng, mdk3, mdk4)")
            Deauthentication
            ;;
            "Scan for Disassociation attack(mdk3, mdk4)")
            Disassociation
            ;;
            "Scan for Authentication DoS(mdk3, mdk4)")
            Authentication
            ;;
            "Scan for Fake AP beacon flood(mdk3, mdk4)")
            BeaconFlood
            ;;
            "Scan for TCP SYN Scan/Stealth Scan(nmap)")
            StealthScan
            ;;
            "Scan for TCP Xmass Scan(nmap)")
            XmassScan
            ;;
            "Back")
            echo "-----------------------------------------------------------------------------------------------------------------------------------"
            mainmenu
            ;;
            *) echo "Invalid option $REPLY";;
        esac
    done
}

#mainmenu
mainmenu(){
echo -e "Select what would you like to do:\n"
PS3="Please select an option: "
options=("Capture live traffic" "Analyze captured file" "Exit")
select opt in "${options[@]}"
do
    case $opt in 
        "Capture live traffic")
        Capture
        ;;
        "Analyze captured file")
        Analyze
        ;;
        "Exit")
        Quit
        ;;
        *) echo "Invalid option $REPLY";;
    esac 
done
}

mainmenu
