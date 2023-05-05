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

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap")

# Get the association request and the handshake number
assoReqNb   = None
eapolNb     = None

for i, packet in enumerate(wpa):
    if packet.haslayer(Dot11AssoReq):
        assoReq = packet
        assoReqNb = i
    elif packet.haslayer(EAPOL):
        eapol = packet
        eapolNb = i
    if assoReqNb and eapolNb:
        break

ssid        = wpa[144][Dot11Beacon].info.decode()
APmac       = a2b_hex(wpa[145][Dot11].addr2.replace(':', ''))
Clientmac   = a2b_hex(wpa[145][Dot11].addr1.replace(':', ''))
PMKID       = wpa[145].original[193:209]

# Read passphrases in wordlist.txt
wordlist = open('wordlist.txt', 'r')
ssid = str.encode(ssid)

print ("\n\nValues used to derivate keys")
print ("============================")
print ("SSID:",ssid,"\n")
print ("AP Mac:",b2a_hex(APmac),"\n")
print ("CLient Mac:",b2a_hex(Clientmac),"\n")
print ("PMKID:", b2a_hex(PMKID),"\n")

# For each passphrase in the wordlist, calculate the PMKID and compare it with the one found in the capture file

for word in wordlist:
    word = word.strip()
    word = str.encode(word)
    
    pmk = pbkdf2(hashlib.sha1, word, ssid, 4096, 32)

    # Calculate PMKID of the passphrase
    pmkid = hmac.new(pmk, b"PMK Name" + APmac + Clientmac, hashlib.sha1).digest()[:16]

    
    # Compare the PMKID with the one found in the capture file
    if pmkid == PMKID:
        print ("Passphrase found:", word)
        print ("PMK:", b2a_hex(pmk))
        print ("PMKID:", b2a_hex(pmkid))
        break
    
    
    
wordlist.close()


