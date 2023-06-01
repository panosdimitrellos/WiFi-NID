# WiFi-NID

![349123291_6195322277252609_8989747047611504562_n](https://github.com/panosdimitrellos/NetSec-Analyzer/assets/34653518/3fd19fda-8080-4c36-9044-ca206bb859cf)


## About

WiFi-NID is a powerful Network Intrusion Detection tool designed to detect various types of attacks in WiFi networks and networks in general. With WiFi-NID, you can capture live traffic and analyze captured files to identify potential security threats. This README provides an overview of the tool's features and instructions on how to use them effectively.

WiFi-NID offers an innovative approach to detecting malicious activity in WiFi networks, by focusing on WiFi specific attack features to identify attacks that originate from the 802.11 layer. As WiFi-NID operates at the edge of the WiFi network, it can be easily integrated as an add-on security mechanism and may be complementary to general IDS solutions that do not focus at the WiFi layer.

## Table of contents 

* [Installation](#installation)
* [Supported features](#supported-features)
  * [Detection of Wireless Network Attacks](#detection-of-wireless-network-attacks)
  * [Detection of Network Attacks](#detection-of-network-attacks)
  * [Detection of Network Port Scanning](#detection-of-network-port-scanning)
  * [Detection of Host Discovery](#detection-of-host-discovery)
  * [Detection of Unauthorized Login Attempts](#detection-of-unauthorized-login-attempts)
* [Examples](#examples)
* [License](#license)
* [Contact](#contact)

## Installation

Ideally, you should be able to just type:
```
git clone https://github.com/panosdimitrellos/WiFi-NID.git 
```

## Supported features

Capture and analyze pcap packets
![image](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/ff7a4e0d-7032-4f77-98fb-0871ffa1585e)

### Detection of Wireless Network Attacks

Using this option we can detect:
* Deauthentication Attacks - from tools like aireplay-ng, mdk3 and mdk4.
* Disassociation Attacks - from tools like mdk3 and mdk4.
* Authentication DoSs - from tools like mdk3 and mdk4.
* Fake AP Beacon Flood - from tools like mdk3 and mdk4.
* WPS Bruteforce Attacks - from tools like reaver and bully.

![image](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/91834c07-2d4d-4c6a-bc4d-514ba5851fec)

### Detection of Network Attacks

Using this option we can detect:
* ARP Poisoning - from tools like arpspoof and ettercap.
* ICMP Flood - from tools like fping and hping.
* VLAN Hopping -  from tools like frogger and yersinia (future work).

![image](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/1d6de77c-da21-48cd-83d3-9e6052d6081c)

### Detection of Network Port Scanning

Using this option we can detect:
* TCP SYN Scan or Stealth Scan - from tools like nmap.
* TCP Xmass Scan - from tools like nmap.
* TCP Null Scan - from tools like nmap.
* TCP FIN Scan - from tools like nmap.
* TCP Connect() Scan - from tools like nmap.
* UDP Port Scan - from tools like nmap.

![image](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/8cbde564-7f5a-429c-8178-cd791beb4af7)

### Detection of Host Discovery

Using this option we can detect:
* ARP Scanning - from tools like arp-scan.
* IP Protocol Scan - from tools like nmap.
* ICMP Ping Sweeps - from tools like nmap.
* TCP Ping Sweeps - from tools like nmap.
* UDP Ping Sweeps - from tools like nmap.

![image](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/1bc3607f-e347-4071-8b68-da14ea384a6d)

### Detection of Unauthorized Login Attempts

This is an ongoing future work on WiFi-NID.

Using this option we can detect:
* SSH Unauthorized Login Attempts
* FTP Unauthorized Login Attempts
* RDP Unauthorized Login Attempts

![image](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/085183d1-fb9b-445d-96f3-0fc7d3f9e732)

## Examples

Here is being presented an example of WiFi-NID tool detecting a Deauthantication attack to view a sample of the resutls containing statistics and observations of the attack.


## License

Nothing for now.

## Contact

email: panosdimitrellos@gmail.com 
