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

def tcplink(sock, addr):
	msg = "Connected to detection server on port 9527!"
	sock.send(msg.encode('utf-8'))
	data = sock.recv(1024)
	print (data.decode('utf-8') + ": %s:%s" % addr)

	# Processing packets from the middle box
	while True:
		pkt_len_pack = sock.recv(4)		# The fixed length of struck pack is 4
		if pkt_len_pack:
			pkt_len = struct.unpack('i', pkt_len_pack)[0]
			pkt_bytes = sock.recv(pkt_len)
			pkt = Ether(pkt_bytes)
			wrpcap('ospf_double_lsa_attack.pcapng', pkt, append=True)
			print ("1 OSPF LSUpd packet has been Received from %s:%s!" % addr)
		else:
			sock.close()
			print('Connection from %s:%s closed.' % addr)
			break
	print('-----------------------------------------------------------------------')

def detection_algorithm():
	with PcapReader('ospf_double_lsa_attack.pcapng') as pcap_reader:
		for pkt in pcap_reader:
			print("Read a packet!")


if __name__ == '__main__':
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(('127.0.0.1', 9527))

	# The maximum number of waiting for connection is 5
	s.listen(5)
	print('Waiting for connection...')

	while True:
		sock, addr = s.accept()
		# Create a new thread to process the new TCP connection
		t = threading.Thread(target=tcplink, args=(sock, addr))
		t.start()

