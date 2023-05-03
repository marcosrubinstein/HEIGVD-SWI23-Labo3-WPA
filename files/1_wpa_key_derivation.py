#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Auteurs : Thomann Yanick, Galley David, Gachet Jean
Date : 03/05/2023

Récupères les informations utiles à la dérivation des clés WPA depuis une capture pcap.
Dérive ensuite les clés

Informations sur l'auteur original:
    __author__      = "Abraham Rubinstein et Yann Lederrey"
    __copyright__   = "Copyright 2017, HEIG-VD"
    __license__ 	= "GPL"
    __version__ 	= "1.0"
    __email__ 		= "abraham.rubinstein@heig-vd.ch"
    __status__ 		= "Prototype"
"""


from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

from custom_tools import get_ssids_and_handshakes


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
wpa=rdpcap("wpa_handshake.cap")

# getting handshakes of ssids
ssids, handshakes = get_ssids_and_handshakes(wpa)
ssid_names = []
for ssid in ssids:  # list all ssid names
    ssid_names.append(ssid)

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = ssid_names[0]  # SWI is the 1st (index 0) and only SSID in the wpa_handshake.cap
handshake   = handshakes[ssid]  # handshake associated with SWI
APmac       = a2b_hex(handshake[0].addr2.replace(':', ''))
Clientmac   = a2b_hex(handshake[0].addr1.replace(':', ''))

# Authenticator and Supplicant Nonces
key_data    = handshake[0][EAPOL].load  # AP nonce is in the 1st message
ANonce      = a2b_hex(key_data[13:45].hex())
key_data    = handshake[1][EAPOL].load  # client nonce is in the 2nd message
SNonce      = a2b_hex(key_data[13:45].hex())

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
key_data    = handshake[3][EAPOL].load
mic_to_test = key_data[-18:-2].hex()

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# Data on which to compute the MIC
dot11_version = b"\x01"  # 802.1X-2001
dott11_type   = b"\x03"  # key
message4_len  = b"\x00\x5f"  # 95 bytes
payload       = handshake[3][EAPOL].load
payload       = payload[0:-18] + b"\x00" * 16 + payload[-2:]  # putting MIC to 0
data          = a2b_hex(dot11_version.hex() + dott11_type.hex() + message4_len.hex() + payload.hex())

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
print ("MIC:\t\t",mic.hexdigest()[:32],"\n")
