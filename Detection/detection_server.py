#! /usr/bin/env python
"""
Detection Server: Receive packets from Middle Box and send the attack recovery instruction
Author:	Alston
Date:	2020.8.7
"""

import socket
import threading
import struct
import subprocess
import redis
from time import *
from threading import Thread
from interval import Interval
from scapy.all import *
load_contrib("ospf")

def recv_from_udp():
	global client_list
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
					# wrpcap('ospf_double_lsa_attack.pcapng', pkt, append=True)
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

def recovery():
	# send the recovery instruction to the Middle Box
	data = str(attack_rec) + "," + victim_router
	client_ip = client_list[0][0]
	# client port for recovery
	client_port = 7890
	s.sendto(data.encode('utf-8'), (client_ip, client_port))
	print("[+] The recovery instruction has been sent.")

def detection_algorithm():
	global malicious_lsa
	head = 0
	tail = 1
	while True:
		start_time = time.time()
		while True:
			try:
				end_time = time.time()
				if end_time - start_time > 5:
					head += 1
					tail = head + 1
				if sliding_window[tail]:
					img_disguised = sliding_window[tail]
					break
			except IndexError:
				print("There are no more LSAs to analyse. Waiting...")
				sleep(10)
				continue
		img_trigger = sliding_window[head]
		while True:
			img_trigger_information = get_lsa_information(img_trigger)
			img_disguised_information = get_lsa_information(img_disguised)
			# Conditions to judge two LSA whether equal
			if img_trigger_information[0] == img_disguised_information[0] - 1 and \
					img_disguised_information[1] - img_trigger_information[1] in Interval(1, 5, closed=False) and \
					img_trigger_information[2:] == img_disguised_information[2:]:
				# Avoid alerting and sending recovery instruction repeatedly
				if malicious_lsa['trigger'] == None and malicious_lsa['disguised'] == None:
					malicious_lsa['trigger'] = img_trigger
					malicious_lsa['disguised'] = img_disguised
				else:
					mal_trigger = malicious_lsa['trigger']
					mal_disguised = malicious_lsa['disguised']
					# The newly captured img_lsa are the same as mal_lsa
					if get_lsa_information(mal_trigger)[0] == img_trigger_information[0] and \
						get_lsa_information(mal_disguised)[0] == img_disguised_information[0]:
						head += 1
						tail = head + 1
						break
					else:
						malicious_lsa['trigger'] = img_trigger
						malicious_lsa['disguised'] = img_disguised
				print('-----------------------------------------------------------------------')
				print("Warning!!!")
				print("The advertising router is: "+str(img_trigger_information[-1]))
				print("Trigger LSA: " + str(img_trigger.summary()))
				print("Disguised LSA: " + str(img_disguised.summary()))
				trigger_bytes = raw(img_trigger)
				disguised_bytes = raw(img_disguised)
				client_ip = client_ip = client_list[0][0]
				client_port = 7891
				trigger_len = struct.pack('i', len(trigger_bytes))
				s.sendto(trigger_len + trigger_bytes + disguised_bytes, (client_ip, client_port))
				print("[+] The two malicious LSAs have been sent to the middle box! ")
				recovery()
				print('-----------------------------------------------------------------------')
				head += 1
				tail = head + 1
				break
			else:
				tail += 1
				break

if __name__ == '__main__':
	#####################################################
	# Initial configuration 							#
	#####################################################

	server_ip = "192.168.37.19"

	# Use networkID+IP to get the name of victim_router
	victim_router = 'r5'

	# Instruction of attack recovery
	attack_rec = True

	#####################################################
	ack_num = 0

	# Used to store multiple Middle Box
	client_list = []

	sliding_window = []

	# Time interval between warning and attack recovery
	hold_time = 10

	malicious_lsa = {'trigger':None, 'disguised':None}

	# UDP Socket
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind((server_ip, 9527))
	t_recv = Thread(target=recv_from_udp, name="receive")
	t_detection = Thread(target=detection_algorithm, name="detection")

	# start the threads
	t_recv.start()
	while True:
		try:
			if sliding_window[0] and sliding_window[1]:
				t_detection.start()
				break
		except IndexError:
			print("Waiting for the coming of first two LSAs...")
			sleep(10)
			continue
	# wait for child-threads to finish (with optional timeout in seconds)
	t_recv.join()
	t_detection.join()




