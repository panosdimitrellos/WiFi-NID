#!/bin/bash

# Function to check if a command is installed
check_command_installed() {
    command -v "$1" &> /dev/null
}

# Check if tshark is installed
if ! check_command_installed "tshark"; then
    echo "tshark is not installed. Installing..."
    sudo apt-get install tshark -y
else
    echo "tshark is already installed."
fi

# Check if figlet is installed
if ! check_command_installed "figlet"; then
    echo "figlet is not installed. Installing..."
    sudo apt-get install figlet -y
else
    echo "figlet is already installed."
fi

# Check if lolcat is installed
if ! check_command_installed "lolcat"; then
    echo "lolcat is not installed. Installing..."
    sudo apt-get install lolcat -y
else
    echo "lolcat is already installed."
fi
