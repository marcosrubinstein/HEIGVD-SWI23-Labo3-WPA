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

from scapy.all import Dot11Beacon, Dot11, EAPOL, raw, RadioTap


def find_ssid(packets):
    for packet in packets:
        if Dot11Beacon in packet and 'ssid' in packet[Dot11Beacon].network_stats():
            return packet[Dot11Beacon].network_stats()['ssid']
    return None


def get_beacon_addr(packets):
    for packet in packets:
        if Dot11 in packet and packet[Dot11].subtype == 8 and packet[Dot11].type == 0:
            return packet[Dot11].addr2
    return None


def get_client_addr(packets):
    for packet in packets:
        if Dot11 in packet and packet[Dot11].subtype == 11 and packet[Dot11].type == 0:
            return packet[Dot11].addr1
    return None


def get_anonce(packets):
    for packet in packets:
        if EAPOL in packet and packet[Dot11].FCfield == 2 and packet[Dot11].subtype == 0:
            return packet[EAPOL].load[13:45]


def get_snonce(packets):
    for packet in packets:
        if EAPOL in packet and packet[Dot11].FCfield == 1 and packet[Dot11].subtype == 8:
            return packet[EAPOL].load[13:45]


def get_mic(packets):
    for packet in packets:
        if RadioTap in packet and packet[RadioTap].present.MCS and Dot11 in packet and packet[Dot11].FCfield == 1 and packet[Dot11].SC == 16:
            return packet[EAPOL].load[77:93]
