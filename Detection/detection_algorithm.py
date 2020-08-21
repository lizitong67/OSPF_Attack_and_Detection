#! /usr/bin/env python
"""
Detection Algorithm
Author:	Alston
Date:	2020.8.20
"""
from scapy.all import *
load_contrib("ospf")
from time import *

# packets = rdpcap('ospf_double_lsa_attack.pcapng')
#
# print (packets[0].show())
#
# if OSPF_LSUpd in packets[0]:
#     print("yes!")

with PcapReader('ospf_double_lsa_attack.pcapng') as pcap_reader:
    while True:
        packet = next(pcap_reader)
        print ("1 packet!")
        sleep(2)


