#!/bin/bash

container=$1
interface=$2
iflink=$(lxc exec $1 cat /sys/class/net/$2/iflink)
veth=$(grep -l $iflink /sys/class/net/veth*/ifindex)
veth=$(echo $veth|sed -e 's;^.*net/\(.*\)/ifindex$;\1;')
echo $veth