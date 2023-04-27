#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Scaircrack

Script to test multiple passwords from a file, creates a MIC with it and compares it with the one retrieve in the last packet of the 4-way handshake.
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 	= "abraham.rubinstein@heig-vd.ch"
__status__ 	= "Prototype"
__modified_by__ = "Valzino Benjamin, Tissot Olivier, Bailat Joachim"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
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

# Read capture file
wpa=rdpcap("wpa_handshake.cap") 

ssid        = wpa[0].info.decode() ###### A COMMENTER
APmac       = a2b_hex(wpa[0].addr2.replace(":","")) ###### A COMMENTER
Clientmac   = a2b_hex(wpa[1].addr1.replace(":","")) ###### A COMMENTER

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex(wpa[5][EAPOL].load[13:45].hex()) ###### A COMMENTER
SNonce      = a2b_hex(bytes(wpa[6])[65:97].hex()) ######### A COMMENTER
    
ssid = str.encode(ssid)


data        = wpa[8].original[48:-18] + b'\0' * 16 + wpa[8].original[-2:]
mic_to_test = wpa[8].original[-18:-2].hex() # SO IT LOOKS GOOD

# Open wordlist
passphrases =  open("wordlist.txt", 'r')
# Read every word in worlist 
for passphrase in passphrases:
    
    A    = "Pairwise key expansion"
    B    = min(APmac, Clientmac)+max(APmac, Clientmac)+min(ANonce, SNonce)+max(ANonce, SNonce)
    data = wpa[8].original[48:-18] + b'\0' * 16 + wpa[8].original[-2:]
    
    passphrase = passphrase.replace("\n", "")
    passphrase = str.encode(passphrase)
    pmk = pbkdf2(hashlib.sha1,passphrase, ssid, 4096, 32)
    ptk = customPRF512(pmk,str.encode(A),B)
    mic_passphrase = hmac.new(ptk[0:16],data,hashlib.sha1).hexdigest()[:32]

    if(mic_passphrase == mic_to_test):
        print("/!\ Password found : ", passphrase.decode(), "/!\ ")
        exit(0)
    
    print("Password incorrect : ", passphrase.decode())

print("No corresponding password found")
exit(1)
