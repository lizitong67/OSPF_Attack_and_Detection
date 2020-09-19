#! /usr/bin/env python
"""
Middle Box
Author:	Alston 					  
Date:	2020.7.26  
"""

import subprocess
import socket
import struct
from select import *
from threading import Thread
from time import *
from scapy.all import *
load_contrib("ospf")

def get_veth():
	veth_list = []
	for device, interface in device_if:
		cmd = './lxd_vethfinder.sh '+device+' '+interface
		res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
		veth = res.communicate()[0].replace('\n','')
		veth_list.append(veth)
	print('[+] The veth interfaces have been obtained!')
	return veth_list


def send_to_analyser(pkt):
	# OSPF_Hdr/OSPF_LSUpd/.lsalist/OSPF_Router_LSA || OSPF_Network_LSA ||....

	if OSPF_Router_LSA in pkt:
		global pkt_num
		# 'h' represents the short int which length is 2 bytes
		pkt_num_field = struct.pack('h', pkt_num % 65535)
		pkt_bytes = raw(pkt)
		# Attach the pkt_num to pkt so as to implement the stop-and-wait protocol
		s.sendto(pkt_num_field + pkt_bytes, (server_ip, 9527))
		wrpcap('md.pcapng', pkt, append=True)
		# Reliable data transfer
		# Timeout timer = 1s
		s.settimeout(1)
		try:
			ack_num = struct.unpack('h', s.recvfrom(2)[0])[0]
		except:
			ack_num = -1
			print("Time out!")
		s.settimeout(None)

		# Retransmission only once
		if ack_num !=  pkt_num:
			s.sendto(pkt_num_field + pkt_bytes, (server_ip, 9527))
			ack_num = struct.unpack('h', s.recvfrom(2)[0])[0]
			print("The OSPF LSUpd packet #%d sent failed and has been retransmitted!" % pkt_num)
			pkt_num += 1
		else:
			print("The OSPF LSUpd packet #%d has been sent to detection server!" % pkt_num)
			pkt_num += 1


def packet_capture():
	print('[+] Starting sniffing the Link State Update packets of the target network...')
	pkts = sniff(filter="proto ospf", iface=veth_list, prn=send_to_analyser)


if __name__ == '__main__':
	server_ip = "192.168.37.32"
	client_ip = '192.168.72.216'
	device_if = [['r1', 'eth0'],
				 ['r1', 'eth1'],
				 ['r3', 'eth0'],
				 ['r3', 'eth1']
				]
	pkt_num = 0
	print('-----------------------------------------------------------------------')
	veth_list = get_veth()
	print('-----------------------------------------------------------------------')
	# UDP Socket
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind((client_ip, 11111))
	# Send
	msg = b'Middle Box #1'
	s.sendto(msg, (server_ip, 9527))
	# Receive
	print(s.recvfrom(1024)[0].decode('utf-8'))
	print('-----------------------------------------------------------------------')
	packet_capture()
	print('-----------------------------------------------------------------------')






