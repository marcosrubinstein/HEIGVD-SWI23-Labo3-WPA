#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Modifié par:
# Anthony Coke
# Guilain Mbayo
# Mehdi Salhi

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
import binascii
import os

# Fonction pour extraire un 4-way handshake
def extract_handshake(packets):
    # Définir les flags pour chaque étape du handshake
    flags = {"SYN": 0x02, "ACK": 0x10, "FIN": 0x01}
    # Initialiser les dictionnaires pour stocker les paquets de chaque étape
    syn_packets = {}
    syn_ack_packets = {}
    ack_packets = {}

    # Parcourir tous les paquets capturés
    for packet in packets:
        # Vérifier si le paquet est un paquet SYN
        if packet.haslayer(TCP) and packet[TCP].flags == flags["SYN"]:
            syn_packets[packet[TCP].seq] = packet
        # Vérifier si le paquet est un paquet SYN-ACK
        elif packet.haslayer(TCP) and packet[TCP].flags == (flags["SYN"] | flags["ACK"]):
            syn_ack_packets[packet[TCP].ack] = packet
        # Vérifier si le paquet est un paquet ACK
        elif packet.haslayer(TCP) and packet[TCP].flags == flags["ACK"]:
            ack_packets[packet[TCP].seq] = packet

    # Parcourir tous les paquets SYN et SYN-ACK pour trouver un match
    for syn_seq, syn_packet in syn_packets.items():
        for syn_ack_ack, syn_ack_packet in syn_ack_packets.items():
            if syn_seq + 1 == syn_ack_ack:
                for ack_seq, ack_packet in ack_packets.items():
                    if syn_ack_ack + 1 == ack_seq:
                        # Retourner le handshake complet
                        return (syn_packet, syn_ack_packet, ack_packet)
    # Si aucun handshake n'est trouvé, retourner None
    return None

# Fonction pour afficher les informations sur le handshake
def print_handshake(handshake):
    if handshake:
        print("Handshake capturé :")
        print(handshake[0].summary())
        print(handshake[1].summary())
        print(handshake[2].summary())
    else:
        print("Aucun handshake n'a été capturé.")

# Configure the network interface in monitor mode (interface may have to be
# changed)
interface = "wlan0mon"
os.system(f"sudo ip link set {interface} down")
os.system(f"sudo iw dev {interface} set type monitor")
os.system(f"sudo ip link set {interface} up")

# set the list of Wi-Fi channels to scan
channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]

for channel in channels:
    os.system(f"sudo iwconfig {interface} channel {channel}")
    print(f"Scanning channel {channel}...")

    # Capturer les paquets sur l'interface réseau spécifiée
    packets = sniff(iface=interface, filter="tcp", count=0, timeout=10)

    # Extraire le 4-way handshake
    handshake = extract_handshake(packets)

    if handshake != None:
        break

# Afficher les informations sur le handshake
print_handshake(handshake)

