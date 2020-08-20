#!binbash

# usage: ./lxd_vethfinder.sh container_name interface_nam

container=$1
interface=$2
iflink=$(lxc exec $1 cat sysclassnet$2iflink)
veth=$(grep -l $iflink sysclassnetvethifindex)
veth=$(echo $vethsed -e 's;^.net(.)ifindex$;1;')
echo $veth