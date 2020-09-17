#!/bin/bash

victim=$1


eth0=$(lxc info $1 | grep eth0 | sed -n 1p | sed -e 's/eth0:\sinet\s\(.*\)veth\(.*\)/\1/g')
subnet=$(echo $eth0 | sed -e 's/\(.*\.\)\(.*\.\)\(.*\.\)\(.*\)/\1\2\30\/24/g')

lxc exec $1 bash <<EOF
vtysh <<EEOF
conf ter
router ospf
no network $subnet area 0
network $subnet area 0
exit
EEOF
exit
EOF