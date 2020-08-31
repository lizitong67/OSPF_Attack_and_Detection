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

def get_lsa_information(pkt, lsa_num=0):
	# Suppose that only 1 LSA in the lsalist
	seq = pkt[OSPF_LSUpd].lsalist[lsa_num][OSPF_Router_LSA].seq
	time = pkt.time
	link_state_id = pkt[OSPF_LSUpd].lsalist[lsa_num][OSPF_Router_LSA].id
	advertising_router = pkt[OSPF_LSUpd].lsalist[lsa_num][OSPF_Router_LSA].adrouter
	return seq, time, link_state_id, advertising_router

def detection_algorithm():
	global sliding_window
	head = 0
	while True:
		img_trigger = sliding_window[head]
		tail = head+1
		while Ture:
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

			elif img_disguised_information[1]-img_trigger_information[1] >= 5:
				head += 1
				break
			else:
				while True:
					if sliding_window[tail+1]:
						tail += 1
						break

if __name__ == '__main__':
	ack_num = 0
	sliding_window = [None]
	# UDP Socket
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind(('127.0.0.1', 9527))
	t_recv = Thread(target=recv_from_udp, name="receive")
	t_detection = Thread(target=detection_algorithm, name="detection")
	t_recv.start()
	# while True:
	# 	if sliding_window[0] and sliding_window[1]:
	# 		t_detection.start()
	# 		break
	t_recv.join()
	# t_detection.join()




