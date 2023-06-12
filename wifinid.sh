#! /bin/bash

# sudo apt-get install tshark 
# sudo apt-get install figlet
# sudo apt-get install lolcat

LRED="\e[91m"
GREEN="\e[32m"
CYAN="\e[36m"
ENDCOLOR="\e[0m"

echo -e "Welcome to WiFi-NID :) \n"

echo "
       @@@@@  @@@@@ @@@@@@      @@@@@@@@@@@               @@@@@@   @@@@@ @@@@@ @@@@@&&&@@@@@@
      @@@@@@.@@@@@.@@@@@@.@@@@.@@@@@@.......@@@@@        @@@@@@@.&@@@@@.@@@@@.@@@@@....@@@@@.
      @&&@@.&@&@@..@&&@@.@&&@@.@&&&&######@.@&&@.%((((% @&&&@@@&#%&&@@.@@@@@.@&&&@@. .@&&@@.
     @@@@@..@@@@,.@@@@@,@@@@@,@@@@@,.......@@@@@.......@@@@@@,@@@@@@@,@@@@@,@@@@@@...@@@@@#
     @@&&@@@@@&@@@@&&@.@@@@@.@@&@@..      @@@@@.      #@@&@@...@@&@&,@@@@@,&@&@@@@@&@@@&@.
" | lolcat

echo -e "                                                                      By Panagiotis Dimitrellos"
echo -e "                                                   https://github.com/panosdimitrellos/WiFi-NID\n"


Deauthentication(){
    echo "-------------------------------------------------------------------------------------------------------------------------------------"
    echo -e  "${LRED}Full report of Deauthentication Frames:\n${ENDCOLOR}"
    echo "frame.number      wlan.sa               wlan.da                         frame.time"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 12)' -n -t ad -T fields -e frame.number -e wlan.sa -e wlan.da -e frame.time
    echo -e "${LRED}\nDeauthentication frames statistics:\n${ENDCOLOR}"
    echo "Packets      Source            Destination"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 12)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | sort -rnk1,1
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r "$pcap_file" -Y '(wlan.fc.type_subtype == 12)' -n | grep -q '.*'; then
        # extract the source and packet count for the line with the most packets
        most_packets=$(tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 12)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | sort --numeric-sort --reverse | head -1)
        # extract the packet count and source from the most_packets variable
        packet_count=$(echo $most_packets | awk --field-separator ' ' '{ print $1 }')
        source=$(echo $most_packets | awk --field-separator ' ' '{ print $2 }')
        # compare the packet count to a threshold value to determine if it indicates a possible attack
        if [ $packet_count -gt 50 ]; then
            echo -e "   Deauthentication DoS attack detected involving MAC address $source due to high number of Deauthentication packets."
            echo -e "   If this happens in a high volume and in a small period of time, that indicates a high possibility of such an attack."
        else
            echo -e "   No indication of malicious packets found."
        fi
    else
        echo -e "   No indication of malicious packets found."
    fi
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOWNA
}

Disassociation(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of Disassociation Frames:\n${ENDCOLOR}"
    echo "frame.number      wlan.sa               wlan.da                         frame.time"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 10)' -n -t ad -T fields -e frame.number -e wlan.sa -e wlan.da -e frame.time
    echo -e "${LRED}\nDisassociation frames statistics:\n${ENDCOLOR}"
    echo "Packets      Source            Destination"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 10)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | sort -rnk1,1
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r "$pcap_file" -Y '(wlan.fc.type_subtype == 10)' -n | grep -q '.*'; then
        # extract the source and packet count for the line with the most packets
        most_packets=$(tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 10)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | sort --numeric-sort --reverse | head -1)
        # extract the packet count and source from the most_packets variable
        packet_count=$(echo $most_packets | awk --field-separator ' ' '{ print $1 }')
        source=$(echo $most_packets | awk --field-separator ' ' '{ print $2 }')
        # compare the packet count to a threshold value to determine if it indicates a possible attack
        if [ $packet_count -gt 50 ]; then
            echo -e "   Disassociation DoS attack detected involving MAC address $source due to high number of Disassociation packets."
            echo -e "   If this happens in a high volume and in a small period of time, that indicates a high possibility of such an attack."
        else
            echo -e "   No indication of malicious packets found."
        fi
    else
        echo -e "   No indication of malicious packets found."
    fi
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOWNA
}

Authentication(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of Authentication Frames:\n${ENDCOLOR}"
    echo "frame.number      wlan.sa               wlan.da                         frame.time"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 11)' -n -t ad -T fields -e frame.number -e wlan.sa -e wlan.da -e frame.time
    echo -e "${LRED}\nAuthentication frames statistics:\n${ENDCOLOR}"
    echo "Packets      Source            Destination"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 11)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | sort -rnk1,1
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 11)' -n | grep -q '.*'; then
        targets=$(tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 11)' -n | awk '{print $5}' | sort | uniq --count | awk '$1 > 100 {print "   ", $2, "was targeted", $1, "times."}')
        if [ ! -z "$targets" ]; then
            echo -e "   Authentication DoS attack detected due to high number of Authentication packets comming from multiple MAC addresses."
            echo -e "   Targeted MACs:\n$targets\n"
        else
            echo -e "   No indication of malicious packets found."
        fi
    else
        echo -e "   No indication of malicious packets found."
    fi 
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOWNA
}

BeaconFlood(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Fake Ap Beacon Flood statistics:\n${ENDCOLOR}"
    echo "Packets    MAC address           SSID"
    tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 8) && (frame.len < 150) ' -n | awk --field-separator ' ' '{ print $3 " " $14}' | sort | uniq --count
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 8) && (frame.len < 150) ' -n | awk --field-separator ' ' '{ print $3 " " $14}' | sort | uniq --count| grep -q '.*'; then
        ssid_count=$(tshark -r $pcap_file -Y '(wlan.fc.type_subtype == 8) && (frame.len < 150) ' -n | awk --field-separator ' ' '{ print $14 }' | sort | uniq -c | wc -l)
        if [ $ssid_count -gt 50 ]; then
            echo -e "   Beacon Flood attack detected due to high number of random beacons."
            echo -e "   If this happens in a high volume and in a small period of time, that indicates a high possibility of such an attack."
        else
            echo -e "   No indication of malicious packets found."
        fi
    else
        echo -e "   No indication of malicious packets found."
    fi
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOWNA
}

WPSBruteforce(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of WPS failed Authentication Frames:\n${ENDCOLOR}"
    echo "frame.number      wlan.sa               wlan.da                         frame.time"
    tshark -r $pcap_file -Y '(wps.configuration_error == 0x0012)' -n -t ad -T fields -e frame.number -e wlan.sa -e wlan.da -e frame.time
    echo -e "${LRED}\nWPS failed Authentication frames statistics:\n${ENDCOLOR}"
    echo "Packets      Source            Destination"
    tshark -r $pcap_file -Y '(wps.configuration_error == 0x0012)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '(wps.configuration_error == 0x0012)' -n | grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '(wps.configuration_error == 0x0012)' -n | awk '{print $5}' | sort | uniq --count | awk '{print "   ", $2}')
        targets=$(tshark -r $pcap_file -Y '(wps.configuration_error == 0x0012)' -n | awk '{print $3}' | sort | uniq --count | awk '$1 > 3 {print "   ", $2, "was targeted", $1, "times."}')
        if [ ! -z "$targets" ]; then
            echo -e "   WPS bruteforce attack detected due to high number of EAP packets of WPS with Device Password Authentication Error."
            echo -e "   Targeted MACs:\n$targets"
            echo -e "   Malicious MACs:\n$malicious\n"
        else
            echo -e "   No indication of malicious packets found."
        fi
    else
        echo -e "   No indication of malicious packets found."
    fi 
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOWNA
}

StealthScan(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of TCP SYN Scan Technique${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst     tcp.srcport tcp.dstport         frame.time"
    tshark -r $pcap_file -Y '(tcp.window_size_value <= 1024 and tcp.hdr_len == 24 and tcp.flags == 0x002)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time
    echo -e "\n${LRED}TCP SYN Scan Technique statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '(tcp.window_size_value <= 1024 and tcp.hdr_len == 24 and tcp.flags == 0x002)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '(tcp.window_size_value <= 1024 and tcp.hdr_len == 24 and tcp.flags == 0x002)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '(tcp.window_size_value <= 1024 and tcp.hdr_len == 24 and tcp.flags == 0x002)' -n | awk '{print $3}' | sort | uniq --count | awk '{print "   ", $2}')
        targets=$(tshark -r $pcap_file -Y '(tcp.window_size_value <= 1024 and tcp.hdr_len == 24 and tcp.flags == 0x002)' -n | awk --field-separator ' ' '{ print $5 }' | sort | uniq | awk '{ print "   ", $1 }')
        echo -e "   TCP SYN/Stealth Scan detected. These TCP SYN scans propably came from Nmap tool."
        echo -e "   Targeted IPs:\n$targets"
        echo -e "   Malicious IPs:\n$malicious\n"
    else
        echo -e "   No indication of malicious packets found."
    fi    
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DONPS
}

XmassScan(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of TCP Xmass Scan Technique${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst     tcp.srcport tcp.dstport         frame.time"
    tshark -r $pcap_file -Y '((tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1) && (tcp.window_size_value == 1024)) && (tcp.hdr_len == 20)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time
    echo -e "${LRED}\nTCP Xmass Scan Technique statistics:\n${ENDCOLOR}"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '((tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1) && (tcp.window_size_value == 1024)) && (tcp.hdr_len == 20)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '((tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1) && (tcp.window_size_value == 1024)) && (tcp.hdr_len == 20)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '((tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1) && (tcp.window_size_value == 1024)) && (tcp.hdr_len == 20)' -n | awk '{print $3}' | sort | uniq --count | awk '{print "   ", $2}')
        targets=$(tshark -r $pcap_file -Y '((tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1) && (tcp.window_size_value == 1024)) && (tcp.hdr_len == 20)' -n | awk --field-separator ' ' '{ print $5 }' | sort | uniq | awk '{ print "   ", $1 }')
        echo -e "   TCP Xmass Scan detected. These TCP Xmass scans propably came from Nmap tool."
        echo -e "   Targeted IPs:\n$targets"
        echo -e "   Malicious IPs:\n$malicious\n"
    else
        echo -e "   No indication of malicious packets found."
    fi    
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DONPS
}

ConnectScan(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of TCP Connect() Scan Technique${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst     tcp.srcport tcp.dstport         frame.time"
    tshark -r $pcap_file -Y '(tcp.completeness==39)||(tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time
    echo -e "\n${LRED}TCP Connect() Scan Technique statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '(tcp.completeness==39)||(tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | uniq --count | sort -rnk1,1 
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '(tcp.completeness==39)||(tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort -rn | uniq --count| grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '(tcp.completeness==39)||(tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024)' -n | awk '{print $3}' | sort | uniq --count | awk '$1 > 100 {print "   ", $2}')
        targets=$(    tshark -r $pcap_file -Y '(tcp.completeness==39)||(tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024)' -n | awk --field-separator ' ' '{ print $5 }' | sort | uniq -c | sort -rn | awk '$1 > 100 { print "   ", $2 }')
        echo -e "   TCP Connect() Nmap Scan detected. These TCP Connect() scans propably came from Nmap tool"
        echo -e "   This scan is being detected if the attacker performs a scanning on more than 100 ports."
        echo -e "   Targeted IPs:\n$targets"
        echo -e "   Malicious IPs:\n$malicious\n"
        echo -e "   To further investigate this attack, check the TCP Conversation Completeness in Wireshark with the filter 'tcp.completeness==39'."
        echo -e "   Number 39 indicates that no data was transferred in the conversations and no FIN flags were set, which is considered suspicious."
        echo -e "   If WiFi-NID also displayed a large amount of packets this indicates a TCP Connect() Nmap Scan."
    else
        echo -e "   No indication of malicious packets found."
    fi    
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DONPS 
}

NullScan(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of TCP NULL Scan Technique${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst     tcp.srcport tcp.dstport         frame.time"
    tshark -r $pcap_file -Y '(tcp.flags==0)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time
    echo -e "\n${LRED}TCP NULL Scan Technique statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '(tcp.flags==0)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '(tcp.flags==0)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count| grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '(tcp.flags==0)' -n | awk '{print $3}' | sort | uniq --count | awk '{print "   ", $2}')
        targets=$(tshark -r $pcap_file -Y '(tcp.flags==0)' -n | awk --field-separator ' ' '{ print $5 }' | sort | uniq | awk '{ print "   ", $1}')
        echo -e "   TCP NULL Scan detected. These TCP NULL scans propably came from Nmap tool."
        echo -e "   Targeted IPs:\n$targets"
        echo -e "   Malicious IPs:\n$malicious\n"
    else
        echo -e "   No indication of malicious packets found."
    fi  
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DONPS 
}

FinScan(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of TCP FIN Scan Technique${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst     tcp.srcport tcp.dstport         frame.time"
    tshark -r $pcap_file -Y '(tcp.flags==0x001)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time
    echo -e "\n${LRED}TCP FIN Scan Technique statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '(tcp.flags==0x001)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '(tcp.flags==0x001)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count| grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '(tcp.flags==0x001)' -n | awk '{print $3}' | sort | uniq --count | awk '{print "   ", $2}')
        targets=$(tshark -r $pcap_file -Y '(tcp.flags==0x001)' -n | awk --field-separator ' ' '{ print $5 }' | sort | uniq | awk '{ print "    ", $1 }')
        echo -e "   TCP FIN Scan detected. These TCP FIN scans propably came from Nmap tool."
        echo -e "   Targeted IPs:\n$targets"
        echo -e "   Malicious IPs:\n$malicious\n"    
    else
        echo -e "   No indication of malicious packets found."
    fi  
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DONPS
}

UdpScan(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of UDP Port Scan Technique${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst     udp.srcport udp.dstport         frame.time"
    tshark -r $pcap_file -Y '(ip.proto == 17) && (udp.length == 8)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e frame.time
    echo -e "\n${LRED}UDP Port Scan Technique statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '(ip.proto == 17) && (udp.length == 8)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '(ip.proto == 17) && (udp.length == 8)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count| grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '(ip.proto == 17) && (udp.length == 8)' -n | awk '{print $3}' | sort | uniq --count | awk '{print "    ", $2}')
        targets=$(tshark -r $pcap_file -Y '(ip.proto == 17) && (udp.length == 8)' -n | awk --field-separator ' ' '{ print $5 }' | sort | uniq | awk '{ print "    ", $1 }')
        echo -e "   UDP Scan detected. These UDP scans propably came from Nmap tool."
        echo -e "   Targeted IPs:\n$targets"
        echo -e "   Malicious IPs:\n$malicious\n"   
    else
        echo -e "   No indication of malicious packets found."
    fi  
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DONPS
}

SSHLog(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of Unauthorized SSH login attempts${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst     tcp.srcport tcp.dstport         frame.time"
    tshark -r $pcap_file -Y '(tcp.port == 22 and ssh.version == 1 and ssh.auth_success == 0)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time
    echo -e "\n${LRED}Unauthorized SSH login attempts statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '(tcp.port == 22 and ssh.version == 1 and ssh.auth_success == 0)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOULA
}

FTPLog(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of Unauthorized FTP login attempts${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst     tcp.srcport tcp.dstport         frame.time"
    tshark -r $pcap_file -Y '(tcp.port == 21 && ftp.request.command == "USER" && !(ftp.response.code == "230"))' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time
    echo -e "\n${LRED}Unauthorized FTP login attempts statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '(tcp.port == 21 && ftp.request.command == "USER" && !(ftp.response.code == "230"))' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOULA
}

RDPLog(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of Unauthorized RDP login attempts${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst     tcp.srcport tcp.dstport         frame.time"
    tshark -r $pcap_file -Y '(tcp.port == 3389 && rdp.nego.selected_proto == "SSL" && rdp.bmp_compression == 1 && rdp.security.exchange_pkt_id == 1)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time
    echo -e "\n${LRED}Unauthorized RDP login attempts statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '(tcp.port == 3389 && rdp.nego.selected_proto == "SSL" && rdp.bmp_compression == 1 && rdp.security.exchange_pkt_id == 1)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOULA
}

ARPScan(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of ARP frames${ENDCOLOR}"
    echo "frame.number      eth.src              eth.dst                        frame.time"
    tshark -r $pcap_file -Y '(arp.opcode == 1) && !(eth.padding == 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00)' -n -t ad -T fields -e frame.number -e arp.src.hw_mac -e arp.dst.hw_mac -e frame.time
    echo -e "\n${LRED}ARP frames statistics:${ENDCOLOR}\n"
    echo "Packets    Source           Destination"
    tshark -r $pcap_file -Y '(arp.opcode == 1) && !(eth.padding == 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00)' -n -T fields -e arp.src.hw_mac -e arp.dst.hw_mac | awk --field-separator ' ' '{ print $1 " " $2 }' | sort | uniq --count | sort -rnk1,1
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '(arp.opcode == 1) && !(eth.padding == 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00)' -n | grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '(arp.opcode == 1) && !(eth.padding == 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00)' -n | awk '{print $3}' | sort | uniq --count | awk '$1 > 500 {print "   ", $2, "transmitted", $1, "packets."}')
        if [ ! -z "$malicious" ]; then
            echo -e "   ARP Scan detected due to high number of ARP packets being transmitted from a single MAC address."
            echo -e "   Malicious MACs:\n$malicious"
        else
            echo -e "   No indication of malicious packets found."
        fi
    else
        echo -e "   No indication of malicious packets found."
    fi  
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOHD
}

IPProtocolScan(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of IP Protocol scan Technique${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst              frame.time"
    tshark -r $pcap_file -Y '(ip.version == 4) && (frame.protocols == "sll:ethertype:ip")' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e frame.time
    echo -e "\n${LRED}IP Protocol scan statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '(ip.version == 4) && (frame.protocols == "sll:ethertype:ip")' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | sort -rnk1,1
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '(ip.version == 4) && (frame.protocols == "sll:ethertype:ip")' -n | grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '(ip.version == 4) && (frame.protocols == "sll:ethertype:ip")' -n | awk '{print $3}' | sort | uniq --count | awk '$1 > 500 {print "   ", $2}')
        targets=$(tshark -r $pcap_file -Y '(ip.version == 4) && (frame.protocols == "sll:ethertype:ip")' -n | awk '{print $5}' | sort | uniq --count | awk '$1 > 500 {print "   ", $2}')
        if [ ! -z "$malicious" ]; then
            echo -e "   IP Protocol Scan detected due to high number of IPv4 packets being transmitted from a single IP address."
            echo -e "   Target IPs:\n$targets"
            echo -e "   Malicious IPs:\n$malicious"
        else
            echo -e "   No indication of malicious packets found."
        fi
    else
        echo -e "   No indication of malicious packets found."
    fi  
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOHD
}

ICMPPingSweeps(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of ICMP Ping Sweeps Technique${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst              frame.time"
    tshark -r $pcap_file -Y '(icmp.type==8 or icmp.type==0)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e frame.time
    echo -e "\n${LRED}ICMP Ping Sweeps statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '(icmp.type==8 or icmp.type==0)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | sort -rnk1,1
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '(icmp.type==8 or icmp.type==0)' -n | grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '(icmp.type==8 or icmp.type==0)' -n | awk '{print $3}' | sort | uniq --count | awk '$1 > 500 {print "   ", $2}')
        if [ ! -z "$malicious" ]; then
            echo -e "   ICMP Ping sweeping detected due to high number of ICMP packets being transmitted from a single IP address targeting"
            echo -e "   a subnet."
            echo -e "   Malicious IPs:\n$malicious"
            echo -e "   If we see a high volume of such traffic destined to many different IP addresses, it means somebody is probably performing"
            echo -e "   ICMP ping sweeping to find alive hosts on the network."
        else
            echo -e "   No indication of malicious packets found."
        fi
    else
            echo -e "   No indication of malicious packets found."
    fi
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOHD
}

TCPPingSweeps(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of TCP Ping Sweeps Technique${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst             frame.time"
    tshark -r $pcap_file -Y '((ip.version == 4) && (ip.proto == 6) ) && (tcp.window_size_value == 1024)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e frame.time
    echo -e "\n${LRED}TCP Ping Sweeps statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '((ip.version == 4) && (ip.proto == 6) ) && (tcp.window_size_value == 1024)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | sort -rnk1,1
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '((ip.version == 4) && (ip.proto == 6) ) && (tcp.window_size_value == 1024)' -n | grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '((ip.version == 4) && (ip.proto == 6) ) && (tcp.window_size_value == 1024)' -n | awk '{print $3}' | sort | uniq --count | awk '$1 > 500 {print "   ", $2}')
        echo -e "   TCP Ping sweeping detected due to high number of TCP packets being transmitted from a single IP address targeting"
        echo -e "   a subnet."
        echo -e "   Also the packets have window size value 1024 which is very small and unusual and that indicates suspicious traffic."
        echo -e "   Malicious IPs:\n$malicious"
        echo -e "   If we see a high volume of such traffic destined to many different IP addresses, it means somebody is probably performing"
        echo -e "   TCP ping sweeping to find alive hosts on the network."
    else
        echo -e "   No indication of malicious packets found."
    fi 
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOHD
}

UDPPingSweeps(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of UDP Ping Sweeps Technique${ENDCOLOR}"
    echo "frame.number   ip.src     ip.dst              frame.time"
    tshark -r $pcap_file -Y '((ip.version == 4) && (ip.proto == 17) && (ip.len == 68))' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e frame.time
    echo -e "\n${LRED}UDP Ping Sweeps statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '((ip.version == 4) && (ip.proto == 17) && (ip.len == 68))' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | sort -rnk1,1
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '((ip.version == 4) && (ip.proto == 17) && (ip.len == 68))' -n | grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '((ip.version == 4) && (ip.proto == 17) && (ip.len == 68))' -n | awk '{print $3}' | sort | uniq --count | awk '$1 > 500 {print "   ", $2}')
        echo -e "   UDP Ping sweeping detected due to high number of UDP packets being transmitted from a single IP address targeting"
        echo -e "   a subnet."
        echo -e "   Also the packets have 'Total Length' of 68 which is very small and unusual and that indicates suspicious traffic."
        echo -e "   Malicious IPs:\n$malicious"
        echo -e "   If we see a high volume of such traffic destined to many different IP addresses, it means somebody is probably performing"
        echo -e "   UDP ping sweeping to find alive hosts on the network."
    else
        echo -e "   No indication of malicious packets found."
    fi 
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DOHD   
}

ARPPoisoning(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of ARP Poisoning Technique${ENDCOLOR}"
    echo "frame.number          frame.time                     eth.src            eth.dst                     info"
    tshark -r $pcap_file -Y '(arp.duplicate-address-detected or arp.duplicate-address-frame)' -n -n -t ad -T fields -e frame.number -e frame.time -e eth.src -e eth.dst -e _ws.col.Info
    echo -e "\n${LRED}ARP Poisoning statistics:${ENDCOLOR}\n"
    echo "Packets        Source          Destination"
    tshark -r $pcap_file -Y '(arp.duplicate-address-detected or arp.duplicate-address-frame)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | sort -rnk1,1
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '(arp.duplicate-address-detected or arp.duplicate-address-frame)' -n | grep -q '.*'; then
        malicious=$(tshark -r "$pcap_file" -Y '(arp.duplicate-address-detected or arp.duplicate-address-frame)' -n | awk '{ print $3; print $5 }' | sort | uniq --count | sort -rnk1,1 | head -n 1 | awk '{print $2}')
        targets=$(tshark -r $pcap_file -Y '(arp.duplicate-address-detected or arp.duplicate-address-frame)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count | sort -rnk1,1 | awk -v malicious="$malicious" '$2 == malicious && $4 != malicious {print "    " $4}')
        echo -e "   ARP Poisoning attack detected due to ARP duplicate addresses."
        echo -e "   Targeted MACs:\n$targets"
        echo -e "   Malicious MACs\n""    $malicious"
    else
        echo -e "   No indication of malicious packets found."
    fi 
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DONA     

}

ICMPFlood(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of ICMP Flood Technique${ENDCOLOR}"
    echo "frame.number ip.src       ip.dst                                     frame.time"
    tshark -r $pcap_file -Y '((icmp.type == 8 and icmp.code == 0 and data.len > 48) && (data.data == 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00))' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time
    echo -e "\n${LRED}ICMP Flood statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '((icmp.type == 8 and icmp.code == 0 and data.len > 48) && (data.data == 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00))' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "${LRED}\nObservations:\n${ENDCOLOR}"
    if tshark -r $pcap_file -Y '((icmp.type == 8 and icmp.code == 0 and data.len > 48) && (data.data == 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00))' -n | grep -q '.*'; then
        malicious=$(tshark -r $pcap_file -Y '((icmp.type == 8 and icmp.code == 0 and data.len > 48) && (data.data == 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00))' -n | awk '{print $3}' | sort | uniq --count | awk '{print "   ", $2}')
        targets=$(tshark -r $pcap_file -Y '((icmp.type == 8 and icmp.code == 0 and data.len > 48) && (data.data == 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00))' -n | awk '{print $5}' | sort | uniq --count | awk '{print "   ", $2}')        
        echo -e "   ICMP flood attack detected due to multiple ICMP packets transmitted with no data targeting a single IP."
        echo -e "   Targeted IPs:\n$targets"
        echo -e "   Malicious IPs:\n$malicious"
    else
        echo -e "   No indication of malicious packets found."
    fi
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DONA   
}


VLANHopping(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${LRED}Full report of VLAN Hopping${ENDCOLOR}"
    echo "frame.number      wlan.sa               wlan.da                         frame.time"
    tshark -r $pcap_file -Y '(dtp or vlan.too_many_tags)' -n -t ad -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time
    echo -e "\n${LRED}VLAN Hopping statistics:${ENDCOLOR}\n"
    echo "Packets    Source      Destination"
    tshark -r $pcap_file -Y '(dtp or vlan.too_many_tags)' -n | awk --field-separator ' ' '{ print $3 " " $4 " " $5 }' | sort | uniq --count
    echo -e "\n-----------------------------------------------------------------------------------------------------------------------------------\n"
    DONA
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
    if [ ! -f "$pcap_file" ]; then
    echo -e "${LRED}The pcap file '$pcap_file' does not exist. Please provide a valid pcap file path and try again.${ENDCOLOR}"
    Analyze
    else echo -e "Analyze catpured file: ${GREEN}$pcap_file${ENDCOLOR} \n"
    submenu
    fi

}

DOWNA(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${CYAN}Detection of wireless network attacks\n${ENDCOLOR}"
    local PS3="Enter an option: "
    local options=(
        "Scan for Deauthentication attack(aireplay-ng, mdk3, mdk4)" 
        "Scan for Disassociation attack(mdk3, mdk4)" 
        "Scan for Authentication DoS(mdk3, mdk4)" 
        "Scan for Fake AP beacon flood(mdk3, mdk4)"
        "Scan for WPS Bruteforce attack(reaver, bully)"
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
            "Scan for WPS Bruteforce attack(reaver, bully)")
            WPSBruteforce
            ;;
            "Back")
            echo "-----------------------------------------------------------------------------------------------------------------------------------"
            submenu
            ;;
            *) echo "Invalid option $REPLY";;
        esac
    done
}

DONA(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${CYAN}Detection of network attacks\n${ENDCOLOR}"
    local PS3="Enter an option: "
    local options=(
        "Scan for ARP poisoning(arpspoof, ettercap)" 
        "Scan for ICMP flood(fping, hping)" 
        "VLAN hoping(frogger, yersinia)" 
        "Back")
    local opt
    select opt in "${options[@]}"
    do
        case $opt in
            "Scan for ARP poisoning(arpspoof, ettercap)")
            ARPPoisoning
            ;;
            "Scan for ICMP flood(fping, hping)")
            ICMPFlood
            ;;
            "VLAN hoping(frogger, yersinia)")
            VLANHopping
            ;;
            "Back")
            echo "-----------------------------------------------------------------------------------------------------------------------------------"
            submenu
            ;;
            *) echo "Invalid option $REPLY";;
        esac
    done
}

DONPS(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${CYAN}Detection of network port scanning\n${ENDCOLOR}"
    local PS3="Enter an option: "
    local options=(
        "Scan for TCP SYN Scan/Stealth Scan(nmap)"
        "Scan for TCP Xmass Scan(nmap)"
        "Scan for TCP Null Scan(nmap)"
        "Scan for TCP FIN Scan(nmap)"
        "Scan for TCP Connect() Scan(nmap)"
        "Scan for UDP port scan(nmap)"
        "Back")
    local opt
    select opt in "${options[@]}"
    do
        case $opt in
            "Scan for TCP SYN Scan/Stealth Scan(nmap)")
            StealthScan
            ;;
            "Scan for TCP Xmass Scan(nmap)")
            XmassScan
            ;;
            "Scan for TCP Null Scan(nmap)")
            NullScan
            ;;
            "Scan for TCP FIN Scan(nmap)")
            FinScan
            ;;
            "Scan for TCP Connect() Scan(nmap)")
            ConnectScan
            ;;
            "Scan for UDP port scan(nmap)")
            UdpScan
            ;;
            "Back")
            echo "-----------------------------------------------------------------------------------------------------------------------------------"
            submenu
            ;;
            *) echo "Invalid option $REPLY";;
        esac
    done
}

DOHD(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${CYAN}Detection of host discovery (recon)\n${ENDCOLOR}"
    local PS3="Enter an option: "
    local options=(
        "Scan for ARP scanning(arp-scan)"
        "Scan for IP protocol scan(nmap)"
        "Scan for ICMP ping sweeps(nmap)"
        "Scan for TCP ping sweeps(nmap)"
        "Scan for UDP ping sweeps(nmap)"
        "Back")
    local opt
    select opt in "${options[@]}"
    do
        case $opt in
            "Scan for ARP scanning(arp-scan)")
            ARPScan
            ;;
            "Scan for IP protocol scan(nmap)")
            IPProtocolScan
            ;;
            "Scan for ICMP ping sweeps(nmap)")
            ICMPPingSweeps
            ;;
            "Scan for TCP ping sweeps(nmap)")
            TCPPingSweeps
            ;;
            "Scan for UDP ping sweeps(nmap)")
            UDPPingSweeps
            ;;
            "Back")
            echo "-----------------------------------------------------------------------------------------------------------------------------------"
            submenu
            ;;
            *) echo "Invalid option $REPLY";;
        esac
    done
}

DOULA(){
    echo "-----------------------------------------------------------------------------------------------------------------------------------"
    echo -e "${CYAN}Detection of unauthorized login attempts\n${ENDCOLOR}"
    local PS3="Enter an option: "
    local options=(
        "Scan for SSH unauthorized login attempts"
        "Scan for FTP unauthorized login attempts"
        "Scan for RDP unauthorized login attempts"
        "Back")
    local opt
    select opt in "${options[@]}"
    do
        case $opt in
            "Scan for SSH unauthorized login attempts")
            SSHLog
            ;;
            "Scan for FTP unauthorized login attempts")
            FTPLog
            ;;
            "Scan for RDP unauthorized login attempts")
            RDPLog
            ;;
            "Back")
            echo "-----------------------------------------------------------------------------------------------------------------------------------"
            submenu
            ;;
            *) echo "Invalid option $REPLY";;
        esac
    done
}

#submenu
submenu1(){
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


submenu(){
    echo -e "Select the information security concerns you would like to check:\n"
    local PS3="Enter an option: "
    local options=(
        "Detection of wireless network attacks"
        "Detection of network attacks"
        "Detection of network port scanning"
        "Detection of host discovery (recon)"
        "Detection of unauthorized login attempts"
        "Back"
    )
    local opt
    select opt in "${options[@]}"
    do
        case $opt in
            "Detection of wireless network attacks")
            DOWNA
            ;;
            "Detection of network attacks")
            DONA
            ;;
            "Detection of network port scanning")
            DONPS
            ;;
            "Detection of host discovery (recon)")
            DOHD
            ;;
            "Detection of unauthorized login attempts")
            DOULA
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
