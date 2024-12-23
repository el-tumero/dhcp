#!/bin/bash

# Mostek
ip link add br-host type bridge
ip link set dev br-host up

# Namespace'y
for namespace in red green blue yellow
do
ip netns add ns-${namespace}
ip netns exec ns-${namespace} ip link set dev lo up
ip link add vt-${namespace} type veth peer name vt-${namespace}-br
ip link set vt-${namespace} netns ns-${namespace}
ip netns exec ns-${namespace} ip link set vt-${namespace} up
ip link set vt-${namespace}-br master br-host
ip link set dev vt-${namespace}-br up
iptables -A FORWARD -i br-host -j ACCEPT
sudo -u user xterm -xrm 'XTerm.vt100.allowTitleOps: false' -title 'ns-'${namespace} -fa 'Monospace' -fs 12 -bg ${namespace} -fg black -e "sudo ip netns exec ns-${namespace} bash"&
done
