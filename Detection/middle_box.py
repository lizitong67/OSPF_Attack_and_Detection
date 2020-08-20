#! /usr/bin/env python
"""
Middle Box
Author:	Alston 					  
Date:	2020.7.26  
"""

import subprocess
import socket
from scapy.all import *
load_contrib("ospf")



def get_veth(device_if):
	veth_list = []
	for device, interface in device_if:
		cmd = './lxd_vethfinder.sh '+device+' '+interface
		res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
		veth = res.communicate()[0].replace('\n','')
		veth_list.append(veth)

	print ('[+] The veth interfaces have been obtained!')
	return veth_list


def send_to_analyser(pkt):
	# OSPF_Hdr/OSPF_LSUpd/.lsalist/OSPF_Router_LSA || OSPF_Network_LSA
	if OSPF_LSUpd in pkt:
		print ("1 OSPF LSUpd packet has been sent!")
		pkt_bytes = raw(pkt)
		s.send(pkt_bytes)


def packet_capture(veth_list):
	print ('[+] Starting sniffing the Link State Update packets of the target network...')
	pkts = sniff(filter="proto ospf", iface=veth_list, prn=send_to_analyser)
	# wrpcap("test.pcap",package)


if __name__ == '__main__':
	device_if = [['r1', 'eth0'],
				 ['r1', 'eth1'],
				 ['r3', 'eth0'],
				 ['r3', 'eth1']
				]
	print('-----------------------------------------------------------------------')
	veth_list = get_veth(device_if)
	print('-----------------------------------------------------------------------')
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('127.0.0.1', 9527))
	msg = "Connection from Middle Box #1"
	s.send(msg.encode('utf-8'))
	data = s.recv(1024)
	print (data.decode('utf-8'))
	print('-----------------------------------------------------------------------')
	packet_capture(veth_list)
	print('-----------------------------------------------------------------------')





