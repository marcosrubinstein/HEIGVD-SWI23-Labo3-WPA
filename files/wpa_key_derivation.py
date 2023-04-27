#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Custom class to store the SSID and MAC address of an AP   
class SSIDInfo(NamedTuple):
    ssid: str
    mac_address: str

# Function used to get APs from a pcap capture
def find_ssid(pcap_file):
    # Initialize and empty dictionnary to contain APs
    ssids = {}
    # Read all packets in capture
    packets = rdpcap(pcap_file)
    # Iterate over all packets in capture
    for packet in packets:
        # If the packet is a 802.11 beacon
        if packet.haslayer(Dot11Beacon):
            # Retrieve the SSID
            ssid = packet[Dot11Elt].info.decode()
            # Add AP to dict if not seen before
            if ssid not in ssids:
                ssids[ssid] = packet.addr2
    # If there is only one AP found, return its SSID and MAC in an SSIDInfo object
    if len(ssids) == 1:
        ssid, mac = next(iter(ssids.items()))
        return SSIDInfo(ssid=ssid, mac_address=mac)
    # If there are multiple, ask user to choose and return the chosen one
    elif len(ssids) > 1:
        ssid_infos = []
        for ssid, mac in ssids.items():
            ssid_infos.append(SSIDInfo(ssid=ssid, mac_address=mac))
        print("Multiple SSIDs found:")
        for ssid_info in ssid_infos:
            print(f"SSID: {ssid_info.ssid} | MAC Address: {ssid_info.mac_address}")
        chosen_ssid = input("Please choose an SSID by typing its name: ")
        while chosen_ssid not in ssids:
            chosen_ssid = input("Invalid choice. Please choose an SSID by typing its name: ")
        mac = ssids[chosen_ssid]
        return SSIDInfo(ssid=chosen_ssid, mac_address=mac)
    else:
        print("No AP found in capture, exiting...")
        exit()
# Function used to get wifi clients from a wireshark capture
def get_wifi_clients(pcap_file):
    # Initialize and empty dictionnary to contain clients
    clients = {}
    # Read all packets in capture
    packets = rdpcap(pcap_file)
    # Iterate over all the packets
    for packet in packets:
        # If packet is a 802.11 packet
        if packet.haslayer(Dot11):
            # add client to dict if not seen before
            if packet.addr2 not in clients:
                clients[packet.addr2] = 0
            # check if packet is a beacon
            if packet.haslayer(Dot11Beacon):
                # increment beacon count for this client
                clients[packet.addr2] += 1
    # filter out clients that have emitted a beacon
    clients = {k:v for k,v in clients.items() if v == 0}
    # Get the number of 
    num_clients = len(clients)
    # If there is exactly one client, return it's MAC address
    if num_clients == 1:
        return list(clients.keys())[0]
    # If there is more than one client, ask user which to select
    elif num_clients > 1:
        print("Found multiple WiFi clients:")
        for i, client in enumerate(clients.keys()):
            print(f"{i+1}. {client}")
        choice = input("Enter the number of the client to choose: ")
        return list(clients.keys())[int(choice)-1]
    else:
        print("No WiFi clients found, exiting...")
        exit()
# Function used to retrieve WPA nonces from a wireshark capture
def get_wpa_nonce(pcap_file, mac):
    packets = rdpcap(pcap_file)  # read in pcap file
    for packet in packets:
        # check if the packet is a WPA key packet from the AP
        if packet.haslayer(EAPOL) and packet.addr2 == mac:
            # extract the nonce value from the packet's WPA key data
            key_data = packet[EAPOL].load
            nonce = key_data[13:45].hex()
            return nonce
    # if no WPA nonce is found, return None
    return None
# Function used to retrieve the MIC of the 4th packet of the 4-way handshake
def get_wpa_mic(pcap_file, client_mac, ap_mac):
    packets = rdpcap(pcap_file)  # read in pcap file
    for packet in packets:
        # check if the packet is the fourth packet of a 4-way handshake from the client to the AP
        if packet.haslayer(EAPOL) and packet.addr2 == client_mac and packet.addr1 == ap_mac and packet[EAPOL].type == 3:
            # extract the WPA MIC value from the packet's WPA key data
            print(type(packet[EAPOL]))
            key_data = packet[EAPOL].load
            print(key_data.hex())
            mic = key_data[-34:-18].hex()
            return mic
    # if no WPA MIC is found, return None
    return None

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 
print(wpa)

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
# Construct an SsidInfo object from the capture
ssidInfo    = find_ssid("wpa_handshake.cap")
# Get the ssid from the SSIDInfo object
ssid        = ssidInfo.ssid
# Get the mac address from the SSIDInfo object, remove semi-colons and convert to bytes
APmac       = a2b_hex(ssidInfo.mac_address.replace(':',''))
cl_mac  = get_wifi_clients("wpa_handshake.cap")
Clientmac   = a2b_hex(cl_mac.replace(':',''))


# Authenticator and Supplicant Nonces
#ANonce      = a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
ANonce      = a2b_hex(get_wpa_nonce("wpa_handshake.cap", ssidInfo.mac_address))
#SNonce      = a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")
SNonce      = a2b_hex(get_wpa_nonce("wpa_handshake.cap", cl_mac))
# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
#mic_to_test = "36eef66540fa801ceee2fea9b7929b40"
mic_to_test = a2b_hex(get_wpa_mic("wpa_handshake.cap", cl_mac, ssidInfo.mac_address))
print('Mic to test: ', mic_to_test.hex())
B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

print ("\n\nValues used to derivate keys")
print ("============================")
print ("Passphrase: ",passPhrase,"\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")
print ("Client Nonce: ",b2a_hex(SNonce),"\n")

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
ssid = str.encode(ssid)
pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(pmk,str.encode(A),B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)


print ("\nResults of the key expansion")
print ("=============================")
print ("PMK:\t\t",pmk.hex(),"\n")
print ("PTK:\t\t",ptk.hex(),"\n")
print ("KCK:\t\t",ptk[0:16].hex(),"\n")
print ("KEK:\t\t",ptk[16:32].hex(),"\n")
print ("TK:\t\t",ptk[32:48].hex(),"\n")
print ("MICK:\t\t",ptk[48:64].hex(),"\n")
print ("MIC:\t\t",mic.hexdigest(),"\n")
