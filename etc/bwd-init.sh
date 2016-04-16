#!/bin/bash 

set -x

DEV=eth2

/usr/local/sbin/iptables -F FORWARD -t mangle 
/usr/local/sbin/ip6tables -F FORWARD -t mangle 
tc qdisc del dev $DEV root

if [ "$(tc qdisc show dev $DEV | grep htb)" == "" ]; then
	tc qdisc add dev $DEV root handle 1:0 htb
fi

ipset create BWD-SRC hash:net skbinfo counters
ipset create BWD-DST hash:net skbinfo counters

#-t mangle -A INPUT -j SET --map-set test src --map-mark
/usr/local/sbin/iptables -A FORWARD -t mangle -j SET --map-set BWD-SRC src --map-prio
/usr/local/sbin/iptables -A FORWARD -t mangle -j SET --map-set BWD-DST dst --map-prio




