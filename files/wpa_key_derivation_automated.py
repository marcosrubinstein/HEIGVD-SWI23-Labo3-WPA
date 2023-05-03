#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Modifié par:
# Anthony Coke
# Guilain Mbayo
# Mehdi Salhi

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
import binascii

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
aR = ""
handshake = ""
# Iterate over the packets and find the association request layer and the EAPOL
# layer
for i, pkt in enumerate(wpa):
    if aR == "":
        # find the association request, which has the Dot11AssoReq layer
        if pkt.haslayer(Dot11AssoReq):
            aR = pkt
    # find the 4 way handshake, which has the EAPOL layer
    if handshake == "":
        if pkt.haslayer(EAPOL):
            handshake = i
    if aR != "" and handshake != "":
        break

# get the ap and client mac
apMac = wpa[handshake].addr2.replace(":", "")
clientMac = wpa[handshake].addr1.replace(":", "")

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = aR.info.decode()

#ssid        = "SWI"
#APmac       = a2b_hex("cebcc8fdcab7")
#Clientmac   = a2b_hex("0013efd015bd")

APmac       = a2b_hex(apMac)
Clientmac   = a2b_hex(clientMac)

# Authenticator and Supplicant Nonces
#ANonce      = a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
#SNonce      = a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")

# source : https://github.com/k1nd0ne/ScapyWifi/blob/master/ScapyFi.py
ANonce      = wpa[handshake].load[13:45]
SNonce      = wpa[handshake+1].load[13:45]

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
#mic_to_test = "36eef66540fa801ceee2fea9b7929b40"
message_integrity_check = binascii.hexlify(wpa[handshake+3][Raw].load)[154:186]

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

#data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

# Reconstruct the wpa data field and zero out the mic field (info given in the
# README)
wpa_data = binascii.hexlify(bytes(wpa[handshake+3][EAPOL]))
wpa_data = wpa_data.replace(message_integrity_check, b"0" * 32)
wpa_data = binascii.a2b_hex(wpa_data)

print("\n*************************************")
print ("Modified version with automatic values retrieval")
print("\n*************************************")
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
#mic = hmac.new(ptk[0:16],data,hashlib.sha1)
mic = hmac.new(ptk[0:16],wpa_data,hashlib.sha1)


print ("\nResults of the key expansion")
print ("=============================")
print ("PMK:\t\t",pmk.hex(),"\n")
print ("PTK:\t\t",ptk.hex(),"\n")
print ("KCK:\t\t",ptk[0:16].hex(),"\n")
print ("KEK:\t\t",ptk[16:32].hex(),"\n")
print ("TK:\t\t",ptk[32:48].hex(),"\n")
print ("MICK:\t\t",ptk[48:64].hex(),"\n")
print ("MIC:\t\t",mic.hexdigest(),"\n")
