#! /usr/bin/env python
"""
Detection Algorithm
Author:	Alston
Date:	2020.8.20
"""
from scapy.all import *
load_contrib("ospf")
from time import *
import struct

# packets = rdpcap('ospf_double_lsa_attack.pcapng')
#
# print (packets[0].show())
#
# if OSPF_LSUpd in packets[0]:
#     print("yes!")

# with PcapReader('ospf_double_lsa_attack.pcapng') as pcap_reader:
#     while True:
#         packet = next(pcap_reader)
#         print ("1 packet!")
#         sleep(2)

pkt_num = 10
# pkt_num_field = struct.pack('h', pkt_num % 65535)
# dpkg = IP()
# pkt_bytes = raw(dpkg)
# by = pkt_num_field+pkt_bytes
# print(pkt_num_field)
# print(Ether(by[2:]).show())
# print(type(struct.unpack('h',by[0:2])[0]))
addr = ('127.0.0.1', 36972)

# def test():
#     global pkt_num
#     while True:
#         print(pkt_num)
#         pkt_num+=1
#         if pkt_num==12:
#             break
#
# test()

if 9==pkt_num-2:
    print("yes")