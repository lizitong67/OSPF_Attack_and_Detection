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

packets = rdpcap('ospf_double_lsa_attack.pcapng')

while True:
    if 10 > 9:
        if 10 > 8:
            continue
        else:
            print("yes")
    print("ok")



