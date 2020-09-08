#!/bin/bash

victim_router = $1
lxc exec $1 bash <<EOF
vtysh <<EEOF
clear ip ospf interface eth0
exit
EEOF
exit
EOF