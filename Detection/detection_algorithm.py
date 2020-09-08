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
from interval import Interval
import struct

# packets = rdpcap('ospf_double_lsa_attack.pcapng')
#
# print (packets[0].show())
#
# if OSPF_LSUpd in packets[0]:
#     print("yes!")

def get_lsa_information(pkt, lsa_num=0):
    # Suppose that only 1 LSA in the lsalist
    seq = pkt[OSPF_LSUpd].lsalist[lsa_num][OSPF_Router_LSA].seq
    time = pkt.time
    link_state_id = pkt[OSPF_LSUpd].lsalist[lsa_num][OSPF_Router_LSA].id
    advertising_router = pkt[OSPF_LSUpd].lsalist[lsa_num][OSPF_Router_LSA].adrouter
    return seq, time, link_state_id, advertising_router


