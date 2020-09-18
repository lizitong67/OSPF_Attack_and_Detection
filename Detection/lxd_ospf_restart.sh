#!/bin/bash

victim=$1


num=$(echo $1 | sed -e 's/r\(.*\)/\1/g')

#eth0=$(lxc info $1 | grep eth0 | sed -n 1p | sed -e 's/eth0:\sinet\s\(.*\)veth\(.*\)/\1/g')
#subnet=$(echo $eth0 | sed -e 's/\(.*\.\)\(.*\.\)\(.*\.\)\(.*\)/\1\2\30\/24/g')


lxc exec $1 bash <<EOF
vtysh <<EEOF
conf ter
int lo
ip add $num.$num.$num.$num/24
router ospf
network $num.$num.$num.0/24 area 0
no network $num.$num.$num.0/24 area 0
exit
EEOF
exit
EOF