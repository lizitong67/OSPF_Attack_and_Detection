#! /usr/bin/env python
"""
Detection Server
Author:	Alston
Date:	2020.8.7
"""

import socket
import threading
import struct
from scapy.all import *
load_contrib("ospf")

def recv_from_udp():
	client_list=[]
	while True:
		try:
			data, addr = s.recvfrom(1024)
			if addr not in client_list:
				print('Receiving from %s:%s!' % addr)
				s.sendto(b'Hello, %s!' % data, addr)
				client_list.append(addr)
			# Processing packets from the middle box
			else:
				pkt_num = struct.unpack('h', data[0:2])[0]
				pkt = Ether(data[2:])
				global ack_num
				if pkt_num == ack_num:
					# Send to Middle_Box an ACK, whose number is same as the received pkt_num
					s.sendto(data[0:2], addr)
					wrpcap('ospf_double_lsa_attack.pcapng', pkt, append=True)
					print("The OSPF LSUpd packet #%d" % pkt_num + " received from %s:%d!" % addr)
					ack_num += 1
		except:
			print("Error!")
			break
	print('-----------------------------------------------------------------------')

def detection_algorithm():
	with PcapReader('ospf_double_lsa_attack.pcapng') as pcap_reader:
		for pkt in pcap_reader:
			print("Read a packet!")


if __name__ == '__main__':
	# UDP Socket
	ack_num = 0
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind(('127.0.0.1', 9527))
	recv_from_udp()





