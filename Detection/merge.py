#! /usr/bin/env python

import subprocess
import socket
import struct
import redis
from select import *
from threading import Thread
from interval import Interval
from time import *
from scapy.all import *
load_contrib("ospf")


def get_veth():
    veth_list = []
    for device, interface in device_if:
        cmd = './lxd_vethfinder.sh ' + device + ' ' + interface
        res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        veth = res.communicate()[0].replace('\n', '')
        veth_list.append(veth)
    print('[+] The veth interfaces have been obtained!')
    return veth_list


def send_to_analyser(pkt):
    # OSPF_Hdr/OSPF_LSUpd/.lsalist/OSPF_Router_LSA || OSPF_Network_LSA ||....
    if pkt[IP].src in attack_ip:
        # print(pkt.summary())
        # r = redis.Redis(host='127.0.0.1', port=6379)
        key = "lsa_from_attack_router"
        value = str(pkt.summary())
    # r.rpush(key, value)

    if OSPF_Router_LSA in pkt:
        sliding_window.append(pkt)
        print('[+] A OSPF LSA has been captured!')


def packet_capture():
    print('[+] Starting sniffing the Link State Update packets of the target network...')
    pkts = sniff(filter="proto ospf", iface=veth_list, prn=send_to_analyser)


def recovery(attack_rec):
    if attack_rec:
        sleep(7)
        cmd = './lxd_restart_ospf.sh ' + victim_router
        res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        print("[+] The recovery instruction has been sent!")


def store_malicious_lsa(trigger_lsa, disguised_lsa):
        key1 = "trigger_lsa"
        key2 = "disguised_lsa"
        value1 = str(trigger_lsa.summary())
        value2 = str(disguised_lsa.summary())
        # r = redis.Redis(host='127.0.0.1', port=6379)
        # r.set(key1, value1)
        # r.set(key2, value2)
        print("[+] The two malicious LSAs have been stored into the Redis!")

def get_lsa_information(pkt, lsa_num=0):
    # Suppose that only 1 LSA in the lsalist
    seq = pkt[OSPF_LSUpd].lsalist[lsa_num][OSPF_Router_LSA].seq
    time = pkt.time
    link_state_id = pkt[OSPF_LSUpd].lsalist[lsa_num][OSPF_Router_LSA].id
    advertising_router = pkt[OSPF_LSUpd].lsalist[lsa_num][OSPF_Router_LSA].adrouter
    return seq, time, link_state_id, advertising_router


def detection_algorithm():
    global malicious_lsa, img_disguised
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
                store_malicious_lsa(img_trigger, img_disguised)
                recovery(attack_rec)
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
    device_if = [['r1', 'eth0'],
                 ['r1', 'eth1'],
                 ['r3', 'eth0'],
                 ['r3', 'eth1']
                 ]
    # Use networkID+IP to get the name of victim_router
    victim_router = 'r5'
    # Instruction of attack recovery
    attack_rec = True
    # IP address of the attack router
    attack_ip = ["192.168.16.127", "192.168.12.249"]
    #####################################################

    veth_list = get_veth()
    sliding_window = []
    # Time interval between warning and attack recovery
    hold_time = 10
    malicious_lsa = {'trigger': None, 'disguised': None}

    t_capture = Thread(target=packet_capture, name="capture")
    t_detection = Thread(target=detection_algorithm, name="detection")

    t_capture.start()
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
    t_capture.join()
    t_detection.join()
