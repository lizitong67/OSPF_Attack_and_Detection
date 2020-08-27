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
#     while True:
#         packet = next(pcap_reader)
#         print ("1 packet!")
#         sleep(2)
threadRunning = True

def thread_1():
    i = 1
    while threadRunning:
        print("thread 1 " + str(i))
        i += 1
        sleep(1)
def thread_2():
    i = 1
    while threadRunning:
        print("thread 2 " + str(i))
        i += 1
        sleep(1)

t1 = Thread(target=thread_1)
t1.start()
t2 = Thread(target=thread_2)
t2.start()
