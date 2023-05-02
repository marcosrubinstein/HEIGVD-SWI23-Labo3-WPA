#!/bin/bash

hcxpcapngtool -o hash.hc22000 PMKID_handshake.pcap
hashcat -m 22000 hash.hc22000 rockyou.txt.gz
