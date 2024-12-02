#!/usr/bin/env python

'''
CVE-1999-0511
https://nvd.nist.gov/vuln/detail/CVE-1999-0511
Loop to find a random and unused udp dst port above 1024.
ICMP Response; type 5 code 1 - redirect = forwarding
ICMP Response; timeout = no forwarding
'''

# libraries
import argparse
import ipaddress
import psutil
import socket
import random
from termcolor import colored
from scapy.all import *

# main
def main():
    # parse arguments
    parser = argparse.ArgumentParser(
    description="Script for finding IP forwarding in the local subnet")
    parser.add_argument("subnet", type=str, help="Enter the local subnet to check for IP forwading")
    args = parser.parse_args()
    subnet=args.subnet
    
    # check the subnet is valid and output a response message
    subnetIsValid, message = validateConnectedSubnet(subnet)
    print (message)
    if (subnetIsValid == False):
        print(colored(f"Subnet {subnet} was invalid. Try again.", "red"))
        exit();
        
    # scanning for live devices in the subnet
    print(f"\nScanning the subnet {args.subnet} for live devices...\n")
    devices = arpScan(str(args.subnet))
    printARPDevices(devices)
           
    # check each device for IP fowarding
    forwardingHosts = checkForwarding(subnet, devices)
    printForwardingHosts(forwardingHosts)
    
def checkForwarding(subnet, devices):
    # get source MAC and IP address for the subnet
    srcMacAddress, srcIpAddress = getMacAndIpAddressForSubnet(subnet)
    forwardingHosts = []
    # main checking loop
    for device in devices:
        print("Checking " + str(device['ip']) + " with MAC " + str(device['mac']))
        L2=Ether(src=srcMacAddress, dst=device['mac'] ,type=0x0800)
        L3=IP(src=srcIpAddress,dst="169.254." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254)) + "")
        L4=UDP(sport=random.randint(1024, 65535),dport=random.randint(1024, 65535))
        ans, unans = srp(L2/L3/L4, timeout=1, verbose=False)
        # filter on ICMP type 5 code 1
        for snd, rcv in ans:
            if rcv.haslayer(ICMP):
                icmp_type = rcv[ICMP].type
                icmp_code = rcv[ICMP].code
                if (icmp_type == 5 and icmp_code == 1):
                    print("Forwarding received from IP " + device['ip'] + f" with MAC {rcv.src}")
                    forwardingHosts.append(device['ip'])
            else:
                print("No ICMP layer in the response.")
    return forwardingHosts

def validateConnectedSubnet(subnetArg):
    try:
        # validate the subnet as an IPv4 network
        subnet = ipaddress.IPv4Network(subnetArg, strict=False)
        # exclude special addresses
        if subnet.is_loopback:
            return False, colored("Subnet is a loopback network (127.0.0.0/8).", "red")
        if subnet.is_reserved:
            return False, colored("Subnet is a reserved network.", "red")
        if subnet.is_multicast:
            return False, colored("Subnet is a multicast network.", "red")
        # get all connected subnets
        connectedSubnets = []
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    connectedSubnets.append(ipaddress.IPv4Interface(addr.address + '/' + str(addr.netmask)).network)
        # check if the input subnet is one of the connected subnets
        if subnet in connectedSubnets:
            return True, colored(f"Subnet {subnet} is connected.", "green")
        else:
            return False, colored(f"Subnet {subnet} is not connected.", "red")
    except ValueError as error:
        return False, colored(f"Invalid IPv4 subnet: {error}", "red")

def arpScan(subnet):
    # create an ethernet frame with an ARP request
    L2 = Ether(dst="ff:ff:ff:ff:ff:ff")
    L3 = ARP(pdst=subnet)
    packet = L2/L3
    # send the packet and receive responses (timeout is set to 2 seconds)
    result = srp(packet, timeout=2, verbose=False)[0]  
    # prepare a list of MAC and IP pairs
    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

def printForwardingHosts(forwardingHosts):
    print("\nHosts with IP Forwarding:")
    for host in range(0, len(forwardingHosts)):
        print(colored(forwardingHosts[host], "green")) 

def printARPDevices(devices):
    if devices:
        print("IP Address\t\tMAC Address")
        print("-----------------------------------------")
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}")
    else:
        print("No devices found.")
    print(" ")
        
def getMacAndIpAddressForSubnet(subnet):
    # convert the subnet to an ip_network object
    subnet = ipaddress.ip_network(subnet, strict=False)
    # loop over the network interfaces
    for iface, addrs in psutil.net_if_addrs().items():
        # loop over the addresses for each interface
        for addr in addrs:
            # check if the address is an IPv4 address within the subnet
            if addr.family == socket.AF_INET:
                ip_address = addr.address
                # check if the IP address is in the given subnet
                if ipaddress.ip_address(ip_address) in subnet:
                    # get the MAC address for the interface
                    for addr in addrs:
                        if addr.family == psutil.AF_LINK:
                            mac_address = addr.address
                            return mac_address, ip_address
    return None


# main function
if __name__ == '__main__':
	main()

