#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Auteurs : Thomann Yanick, Galley David, Gachet Jean
Date : 03/05/2023

Fonctions utiles pour les exercices 1, 2 et 3.
"""


from scapy.all import *


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


def get_ssids_and_handshakes(pcap, pmkids=False):
    """
    This function returns 2 dictionaries:
        1) ssids: keys = SSID names, values = MAC address of AP
        2) handshakes_or_pmkids: keys = SSID names,
               values =
                   - array of 4 packets constituting a 4-way handshake for the SSID, if pmkids == False
                   - 1st message of a 4-way handshake, if pmkids == True
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
    handshakes_or_pmkids = {}
    for ssid in ssids:
        handshake = {}
        ap_mac = ssids[ssid]
        for pkt in pcap:
            # check if the packet is a WPA key packet from the AP
            if pkt.haslayer(EAPOL):
                # is it the 1st message of a 4-way handshake for the given ssid ? (from AP to client)
                if get_key_info(pkt) == key_infos[0] and pkt.addr2 == ap_mac:  # message 1 of handshake
                    if not pmkids:
                        # add message 1 of handshake in dictionary with key = client MAC
                        handshake[pkt.addr1] = []
                        handshake[pkt.addr1].append(pkt)
                    else:
                        handshakes_or_pmkids[ssid] = pkt
                        break  # a packet with a potential PMKID was found
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
                    handshakes_or_pmkids[ssid] = handshake[pkt.addr2]  # add full 4-way handshake
                    break  # we found a whole 4-way handshake for this ssid
        if ssid not in handshakes_or_pmkids:
            if not pmkids:
                print("No complete 4-way handshake found for {}".format(ssid))
            else:
                print("No first message of a 4-way handshake found for {}".format(ssid))

    return ssids, handshakes_or_pmkids
