# WiFi-NID

![Untitled-1](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/73240a9d-5b6b-478f-8a61-da31eec21ad5)

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

Download the repository from Github as follows:

```
git clone https://github.com/panosdimitrellos/WiFi-NID.git 
```
### Running the Bash Script on Linux

To run WiFi-NID tool on Linux follow these steps:

- Navigate to the directory containing the Bash script using the `cd` command.
- Install the required packages by executing `./install_required_packages.sh`.
- Run the script by executing `./WiFi-NID.sh`.

### Running the Bash Script on Windows

To run WiFi-NID tool on Windows, you can use a Unix-like environment. Here are the steps to follow:

1. **Install a Unix-like environment**:
   - For Git Bash: Download and install Git from the official website: https://git-scm.com/.
   - For Cygwin: Download and run the Cygwin installer from the official website: https://www.cygwin.com/.
   - For Windows Subsystem for Linux (WSL): Follow the official Microsoft documentation to install WSL and choose a Linux distribution: https://docs.microsoft.com/en-us/windows/wsl/.

2. **Run the Bash script**:
   - Open the installed Unix-like environment (e.g., Git Bash, Cygwin, or WSL).
   - Navigate to the directory containing the Bash script using the `cd` command.
   - Run the script by executing `./WiFi-NID.sh`.

Note: Make sure the Bash script has the execute permission. You can set the permission using `chmod +x script.sh`.

## Supported features

Analyze already captured pcap files or capture live traffic and start analyzing them.

![image](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/94f7b6bd-4e98-4d80-8978-5615921890ef)

### Detection of Wireless Network Attacks

Using this option we can detect:
* **Deauthentication Attacks** - from tools like aireplay-ng, mdk3 and mdk4.
* **Disassociation Attacks** - from tools like mdk3 and mdk4.
* **Authentication DoSs** - from tools like mdk3 and mdk4.
* **Fake AP Beacon Flood** - from tools like mdk3 and mdk4.
* **WPS Bruteforce Attacks** - from tools like reaver and bully.

![image](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/7a4d6ee4-177e-4bfa-887e-b8878b538e36)

### Detection of Network Attacks

Using this option we can detect:
* **ARP Poisoning** - from tools like arpspoof and ettercap.
* **ICMP Flood** - from tools like fping and hping.
* **VLAN Hopping** -  from tools like frogger and yersinia (future work).

![image](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/dae284cc-ec0a-4f46-913a-2522c32c3c66)

### Detection of Network Port Scanning

Using this option we can detect:
* **TCP SYN Scan or Stealth Scan** - from tools like nmap.
* **TCP Xmass Scan** - from tools like nmap.
* **TCP Null Scan** - from tools like nmap.
* **TCP FIN Scan** - from tools like nmap.
* **TCP Connect() Scan** - from tools like nmap.
* **UDP Port Scan** - from tools like nmap.

![image](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/5173defd-1497-4573-82be-108aadff2f80)

### Detection of Host Discovery

Using this option we can detect:
* **ARP Scanning** - from tools like arp-scan.
* **IP Protocol Scan** - from tools like nmap.
* **ICMP Ping Sweeps** - from tools like nmap.
* **TCP Ping Sweeps** - from tools like nmap.
* **UDP Ping Sweeps** - from tools like nmap.

![image](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/c225e008-bcfb-4c12-88ba-4be780a7ee1f)

### Detection of Unauthorized Login Attempts

This is an ongoing future work on WiFi-NID.

Using this option we can detect:
* **SSH Unauthorized Login Attempts**
* **FTP Unauthorized Login Attempts**
* **RDP Unauthorized Login Attempts**

![image](https://github.com/panosdimitrellos/WiFi-NID/assets/34653518/fe6b9fbf-e7a9-42fa-8708-19f7cef0d5e7)

## Examples

Here is being presented an example of WiFi-NID tool detecting a Deauthantication attack to view a sample of the resutls containing statistics and observations of the attack.


## License

Nothing for now.

## Contact

email: panosdimitrellos@gmail.com 
