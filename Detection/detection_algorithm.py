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

def dec_alg():
    head = 0
    while True:
        img_trigger = sliding_window[head]
        tail = head+1
        while True:
            img_disguised = sliding_window[tail]

            img_trigger_information = get_lsa_information(img_trigger)
            img_disguised_information = get_lsa_information(img_disguised)
            if img_trigger_information[0] == img_disguised_information[0]-1 and \
                    img_disguised_information[1]-img_trigger_information[1] in Interval(1, 5, closed=False) and \
                    img_trigger_information[2:] == img_disguised_information[2:]:
                print("Warning!")
                print(img_trigger.show())
                print('-----------------------------------------------------------------------')
                print(img_disguised.show())
                head += 1
                break

            elif img_disguised_information[1]-img_trigger_information[1] >= 5:
                head += 1
                break
            else:
                while True:
                    try:
                        if sliding_window[tail+1]:
                            tail += 1
                            break
                    except IndexError:
                        print("There are no more LSA to analyse. Waiting...")
                        sleep(10)
                        continue

# sliding_window = []
# with PcapReader('ospf_double_lsa_attack.pcapng') as pcap_reader:
#     for packet in pcap_reader:
#         sliding_window.append(packet)
#
# dec_alg()

malicious_lsa = {'trigger': [1,], 'disguised': []}
if not (1==1 and 2==3):
    print("YES!")
