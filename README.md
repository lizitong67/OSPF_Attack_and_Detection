# OSPF_Attack_and_Detection



I will talk about an attack against the OSPF protocol published by Alex Kirshon, Dima Gonikman, and Gabi Nakibly during a BlackHat conference. The purpose of this paper is to provide an understanding of the attack and automate it with scripts in a virtual network environment.

# 1 Tool used

- LXD
- FRRouting
- Python Scapy
- Wireshark

# 2 Key points

<u>**The OSPF Fight Back Mechanism**</u>

When a router A receives an LSA and the *Advertising-Router* field equals the *Router-id* of A (The LSA is advertised by A itself), Router A inspects the content and if it is not correct (The routing information of A has tampered), returns immediately another correct LSA which will overwrite the old one.  

<u>**Two LSA are considered identical if they meet the following criteria**</u>

- Same *sequence number* 
- Same *checksum value* 
- Same *age* (+/- 15 min)  

# 3 The attack

![](https://s1.ax1x.com/2020/07/10/UKOUiQ.png)

## Attack steps

**step1:** A **Trigger LSA** specifically craft to usurp an LSA packet from R1 and we send this false LSA to R1 to trigger the fight back mechanism.

**step2:** We send a **Disguised LSA**, which craft to match the **Fight Back LSA** from R1 and carrying false routing information to poison the route table of victims, to R2 simultaneously. That means the Disguised LSA and Fight Back LSA have the same sequence number, checksum, and age, i.e., these two LSA are deemed to be identical.

**step3:** R1 send the Fight Back LSA once receives the Trigger LSA from the attacker, which will be rejected by R2 because R2 already received an equivalent LSA from the attacker forged in step2.

**step4:** R2 flood the Disguise LSA, R1 receives the packet but reject it, being seen as identical to the Fight Back LSA it sent in step 3.  

Thus in the wake of the attack, R1 and R2 have a different LSDB as R2 has a tainted route-table. This continues until the next update of the LSA Database (30 minutes by default)  



# 4 Experiment

![](https://s1.ax1x.com/2020/07/10/UKO2i4.png)

We use the Linux container **LXD** and a shell script to create the network topology automatically. Each router is an Alpine Linux instance with the **FRRouting** build in to conduct the OSPF routing protocol.  

After that, the attack is implemented as follows: 

- Firstly, We sniffing the OSPF packet consecutively in the attack router R1 and stop when the first OSPF LSUpd packet containing Router LSA is received from the victim router R5. We separate the last OSPF LSUpd from the sniffing packets as *original packet* and use it to craft the trigger packet and evil packet for convenience. Besides, sniffing the network without a break in order to launch the attack at any time whenever the victim router sent a LSUpd to revise other router's routing information about itself.
- Secondly, we craft a trigger packet and send it to the victim router in the form of multicast in order to trigger the fightback mechanism of R5. We also send the trigger packet to R6 simultaneously just to guarantee the arriving LSUpd sequence order.
- Eventually, we specifically craft a disguised LSA which same as the fightback LSA sent by R5 and sent the disguised LSA to R6 after 2 seconds cease. The reason why we cease 2 seconds is that the OSPF can only process one LSA per second by default and the fightback mechanism is not triggered until 5 seconds approximately after receiving the trigger LSA. Therefore the time interval between the sending of trigger LSA and disguised LSA should in 1~5 seconds.

By reason of the disguised LSA arrive at R6 before the fightback LSA, the poison target router R6 will add the false routing information carried by the disguised LSA to its routing table. The goal of the attacker is accomplished up to here.

The trigger LSA, disguised LSA, and fightback LSA captured by Wireshark are as follows:

trigger LSA:

![](https://s1.ax1x.com/2020/07/10/UKO4Q1.png)

disguised LSA:

![](https://s1.ax1x.com/2020/07/10/UKOvQI.png)

fightback LSA:

![](https://s1.ax1x.com/2020/07/10/UKXESs.png)

The poisoned routing table of R6 is as follows:

![](https://s1.ax1x.com/2020/07/10/UKXZyq.png)



