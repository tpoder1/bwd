#!/bin/bash 

#set -x

iptables -F FORWARD -t mangle 
ip6tables -F FORWARD -t mangle 

iptables -F FORWARD  
ip6tables -F FORWARD  


tc qdisc del dev eth2 root

ipset destroy BWD-SRC 
ipset destroy BWD-DST 

