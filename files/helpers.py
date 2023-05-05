#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Few helper functions that are common between the different scripts
"""

__author__ = "Hugo Jeanneret et Pascal Perrenoud"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "pascal.perrenoud@heig-vd.ch, hugo.jeanneret@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import Dot11Beacon, Dot11, EAPOL, raw, RadioTap, Dot11Elt


def find_ssid(packets):
    """
    Cette fonction recherche un SSID dans une liste de paquets en se basant le layer Dot11Beacon
    """
    for packet in packets:
        if Dot11Beacon in packet and 'ssid' in packet[Dot11Beacon].network_stats():
            return packet[Dot11Beacon].network_stats()['ssid']
    return None


def get_beacon_addr(packets):
    """
    Cette fonction recherche l'adresse d'un AP dans une liste de paquets en se basant sur leur type et sous-type
    """
    for packet in packets:
        if Dot11 in packet and packet[Dot11].subtype == 8 and packet[Dot11].type == 0:
            return packet[Dot11].addr2
    return None


def get_client_addr(packets):
    """
    Cette fonction recherche l'adresse d'une STA dans une liste de paquets en se basant sur leur type et sous-type
    """
    for packet in packets:
        if Dot11 in packet and packet[Dot11].subtype == 11 and packet[Dot11].type == 0:
            return packet[Dot11].addr1
    return None


def get_anonce(packets):
    """
    Cette fonction recherche le ANonce dans une liste de paquets en se basant sur le FCField et le sous-type du paquet
    """
    for packet in packets:
        if EAPOL in packet and packet[Dot11].FCfield == 2 and packet[Dot11].subtype == 0:
            return packet[EAPOL].load[13:45]


def get_snonce(packets):
    """
    Cette fonction recherche le SNonce dans une liste de paquets en se basant sur le FCField et le sous-type du paquet
    """
    for packet in packets:
        if EAPOL in packet and packet[Dot11].FCfield == 1 and packet[Dot11].subtype == 8:
            return packet[EAPOL].load[13:45]


def get_mic(packets):
    """
    Cette fonction recherche un MIC dans un paquet en se basant sur le flag MCS dans une liste de paquets
    """
    for packet in packets:
        if RadioTap in packet and packet[RadioTap].present.MCS and Dot11 in packet and packet[Dot11].FCfield == 1 and packet[Dot11].SC == 16:
            return packet[EAPOL].load[77:93]


def get_pmkid(packet):
    """
    Cette fonction extrait le PMKID d'un paquet
    """
    '''
    for packet in packets:
        if Dot11Elt in packet and packet[Dot11Elt].ID == 48:
            # Le champ Dot11Elt.ID 48 correspond à RSN IE
            print("PMKID : ", packet[Dot11Elt].info[16:32])
            return packet[Dot11Elt].info[16:32]  # Le PMKID est situé dans les octets 16 à 32 du champ info de RSN IE
    print("PMKID non trouvé")
    return None
    '''
    return packet.original.hex()[386:418]  # Le PMKID est situé à cet endroit dans le paquet
