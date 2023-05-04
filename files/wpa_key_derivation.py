#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""


__author__      = "Abraham Rubinstein et Yann Lederrey"
__editors__     = "Hugo Jeanneret et Pascal Perrenoud"
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
import hmac
import hashlib
import helpers


def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    R    = b''
    for i in range(4):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        R = R+hmacsha1.digest()
    return R[:blen]


# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa         = rdpcap("wpa_handshake.cap")

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
# this string is used in the pseudo-random function
A           = "Pairwise key expansion"

# Récupération des informations de l'AP à partir du fichier pcap
# Previous value : "SWI"
ssid        = helpers.find_ssid(wpa)
# Previous value : a2b_hex("cebcc8fdcab7")
APmac       = a2b_hex(helpers.get_beacon_addr(wpa).replace(':', ''))
# Previous value : a2b_hex("0013efd015bd")
Clientmac   = a2b_hex(helpers.get_client_addr(wpa).replace(':', ''))

# Authenticator and Supplicant Nonces
# Previous value : a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
ANonce      = helpers.get_anonce(wpa)
# Previous value : a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")
SNonce      = helpers.get_snonce(wpa)

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
# Previous value : a2b_hex("36eef66540fa801ceee2fea9b7929b40")
mic_to_test = helpers.find_ssid(wpa)

# used in pseudo-random function
B           = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)

# La seule différence avec le payload du 4-way hand-shake est que le MIC n'est pas présent, il a été remplacé par des 0
# CF "Quelques détails importants" dans la donnée
# Previous value : #a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
data        = list(raw(wpa[8])[48:])
data[17:]   = [0]*82
data        = bytes(data)

print("\n\nValues used to derivate keys")
print("============================")
print(f"Passphrase: {passPhrase}")
print(f"SSID: {ssid}")
print(f"AP Mac: {b2a_hex(APmac)}")
print(f"CLient Mac: {b2a_hex(Clientmac)}")
print(f"AP Nonce: {b2a_hex(ANonce)}")
print(f"Client Nonce: {b2a_hex(SNonce)}")

# calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
ssid = str.encode(ssid)
pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

# expand pmk to obtain PTK
ptk = customPRF512(pmk, str.encode(A), B)

# calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16], data, hashlib.sha1)

print("\nResults of the key expansion")
print("=============================")
print(f"PMK:\t\t{pmk.hex()}")
print(f"PTK:\t\t{ptk.hex()}")
print(f"KCK:\t\t{ptk[0:16].hex()}")
print(f"KEK:\t\t{ptk[16:32].hex()}")
print(f"TK:\t\t{ptk[32:48].hex()}")
print(f"MICK:\t\t{ptk[48:64].hex()}")
print(f"MIC:\t\t{mic.hexdigest()}")
