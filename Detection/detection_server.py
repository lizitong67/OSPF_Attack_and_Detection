#! /usr/bin/env python
"""
Detection Server
Author:	Alston
Date:	2020.8.7
"""

import socket
import threading
import struct
from time import *
from threading import Thread
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
				global ack_num
				global sliding_window
				pkt_num = struct.unpack('h', data[0:2])[0]
				pkt = Ether(data[2:])
				if pkt_num == ack_num:
					# Send to Middle_Box an ACK, whose number is same as the received pkt_num
					s.sendto(data[0:2], addr)
					# If the number of middle_box greater than 1, the packets in this list should be sorted by timestamp
					sliding_window.append(pkt)
					wrpcap('ospf_double_lsa_attack.pcapng', pkt, append=True)
					print("The OSPF LSUpd packet #%d" % pkt_num + " received from %s:%d!" % addr)
					ack_num += 1
		except:
			print("Error!")
			break
	print('-----------------------------------------------------------------------')

def detection_algorithm():
	i = 1
	while True:
		print("test thread " + str(i))
		i += 1
		sleep(3)


if __name__ == '__main__':
	ack_num = 0
	sliding_window = []
	# UDP Socket
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind(('127.0.0.1', 9527))
	t_recv = Thread(target=recv_from_udp, name="receive")
	t_detection = Thread(target=detection_algorithm, name="detection")
	t_recv.start()
	t_detection.start()
	t_recv.join()
	t_detection.join()




