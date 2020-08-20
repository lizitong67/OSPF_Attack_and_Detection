#!/bin/bash
#######################################
#	Creat network topology via LXD    #	
#	Author:	Alston 					  #
#	Date:	2020.7.10                 #
#######################################


ROUTER_NUM=6


HOST_TEMPLATE_NAME="host"
ROUTER_TEMPLATE_NAME="router"

SUBNET=192.168


create_new_container() {
    if [ -d "/var/snap/lxd/common/lxd/containers/$1" ]; 
    then
        echo "Container $1 already exists!"
        return
    fi
    lxc copy ${2} ${1} && echo "Container $1 created!"
}

create(){
    echo "Now create nodes..."
	for router_name in $(seq 1 ${ROUTER_NUM});
	do
		create_new_container r${router_name} ${ROUTER_TEMPLATE_NAME}
	done
}

create_link(){	#create interface and attach network
	
	last_eth=$(lxc config device list ${1} | tail -n 1)
	
	if [[ $last_eth =~ "eth" ]]   #判断子字符串
	then
		new_eth=eth$(( ${last_eth: -1} + 1 ))
		echo "New interface of ${1} is ${new_eth}"
 	
 		lxc start ${1}
		lxc exec ${1} bash <<EOF
chmod 777 /etc/network/interfaces
cat >> /etc/network/interfaces <<EEOF
auto ${new_eth}
iface ${new_eth} inet dhcp
EEOF
exit
EOF
		echo "New interface ${new_eth} of ${1} added!"
	else
		new_eth=eth0
		echo "Interface ${new_eth} of ${1} already exists!"
		lxc start ${1}
	fi

	lxc network attach ${brige_name} ${1} ${new_eth}
	lxc restart ${1}

	echo "New interface ${new_eth} of ${1} is attach to the network ${brige_name}!"
}

config_route(){
	lxc exec ${1} bash <<EOF
rc-service frr start
vtysh <<EEOF
conf ter
router ospf
network ${subnet}.0/24 area 0
do write
end
exit
EEOF
exit
EOF
	echo "route configuration of ${1} is done!"
}


link(){
	echo "Now link ${1} and ${2}..."

	subnet=${SUBNET}.${1: -1}${2: -1}
	network=${subnet}.1/24
	brige_name=${1}${2}
	lxc network create ${brige_name} ipv6.address=none ipv4.address=${network} ipv4.nat=true
	
	create_link ${1}
	create_link ${2}

	config_route ${1}
	config_route ${2}

}

run() {
	for i in $(seq 1 $ROUTER_NUM);
	do
		lxc start r${i}
	done
}


main(){
    local arg
    for arg in $@; 
    do
        local delim=""
        case "$arg" in
            --create)
                args="${args}-c ";;
            --link)
				args="${args}-l ";;
            *)
                [[ "${arg:0:1}" == "-" ]] || delim="\""; args="${args}${delim}${arg}${delim} ";;
       esac
    done

    eval set -- $args    #args中所有的参数可以用$1, $2等来表示

    while getopts "clrvsdh" OPTION;    #$1, $2等分别送入while循环
    do
        case $OPTION in
            c)
                create;;
            l)
				link ${2} ${3};;
            *)
                echo "$PROGNAME -h/--help for help"; exit 0;;
        esac
    done

    return 0
}

main $@


# usage:
# sudo chmod 755 build_network.sh
# sudo ./build_network --create
# sudo ./build_network --link r1 r2
