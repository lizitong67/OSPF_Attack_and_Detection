#! /usr/bin/env python
"""
Detection Algorithm
Author:	Alston
Date:	2020.8.20
"""
from scapy.all import *
load_contrib("ospf")
from threading import Thread
from time import *
import struct

# packets = rdpcap('ospf_double_lsa_attack.pcapng')
#
# print (packets[0].show())
#
# if OSPF_LSUpd in packets[0]:
#     print("yes!")

# with PcapReader('ospf_double_lsa_attack.pcapng') as pcap_reader:
#     for packet in pcap_reader:
#         if OSPF_Router_LSA in packet:
#             print(packet[OSPF_LSUpd].lsalist)
#             print(packet[OSPF_LSUpd].lsalist[0][OSPF_Router_LSA].id)
#             print(packet[OSPF_LSUpd].lsalist[0])
#             print(type(packet[OSPF_LSUpd].lsalist[0]))
#             if OSPF_Router_LSA in packet[OSPF_LSUpd].lsalist:
#                 print ("ok")
#
#             break;
        # print(packet[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].seq)

def test():
    return 1,2,3

x = test()
print (x[1:])
