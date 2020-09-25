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

test = "flase,r5"
l = list(test.split(','))
a, b = l[0], l[1]




