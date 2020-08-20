#! /usr/bin/env python
"""
Detection Server
Author:	Alston 					  
Date:	2020.8.7
"""

import socket
import threading
from scapy.all import *
load_contrib("ospf")

def tcplink(sock, addr):
	msg = "Connected to detection server on port 9527!"
	sock.send(msg.encode('utf-8'))
	data = sock.recv(1024)
	print (data.decode('utf-8') + ": %s:%s" % addr)
	# Processing packets from the middle box
	while True:
		pkt_bytes = sock.recv(4096)
		pkt = Ether(pkt_bytes)
		print ("1 OSPF LSUpd packet has been Received!" )
	sock.close()
	print('Connection from %s:%s closed.' % addr)
	print('-----------------------------------------------------------------------')

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

