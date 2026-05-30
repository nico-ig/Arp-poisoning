# ARP Poisoning Attack Tool

A Python-based ARP poisoning (spoofing) tool for performing man-in-the-middle attacks on local networks.

## Overview

This tool performs ARP poisoning by manipulating ARP tables on both the target device and gateway. It intercepts network traffic between the two devices by making them believe the attacker's MAC address corresponds to the other party's IP address.

## Requirements

- Python 3
- Scapy 2.7.0
- Root/Administrator privileges

## Installation

1. Create a virtual environment:
```bash
python3 -m venv venv
```

2. Activate the environment:
```bash
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the attack using the shell script:
```bash
sudo ./arp-poison.sh -g <gateway_ip> -t <target_ip> -i <interface>
```

### Arguments

- `-g, --gateway`: IPv4 address of the gateway
- `-t, --target`: IPv4 address of the target device
- `-i, --interface`: Network interface to use (e.g., eth0, wlan0)

### Example

```bash
sudo ./arp-poison.sh -g 192.168.1.1 -t 192.168.1.100 -i eth0
```

## How It Works

1. Discovers MAC addresses for the gateway and target using ARP requests
2. Continuously sends ARP spoofing packets to both devices
3. Makes the gateway think the target IP belongs to the attacker's MAC
4. Makes the target think the gateway IP belongs to the attacker's MAC
5. This creates a man-in-the-middle position where traffic flows through the attacker
6. On interruption (Ctrl+C), restores correct ARP table entries

## Stopping the Attack

Press `Ctrl+C` to gracefully stop the attack and restore ARP tables.

## ⚠️ Disclaimer

This tool is provided for **educational purposes only**. Unauthorized ARP poisoning is illegal. Use only on networks you own or have explicit permission to test.
