#!/bin/bash 

#set -x

DEV="bond0"
CHAIN_SRC="FORWARD"
CHAIN_DST="FORWARD"
TC="/usr/sbin/tc"
IPTABLES="/usr/local/sbin/iptables"
IP6TABLES="/usr/local/sbin/ip6tables"
IPSET="/usr/local/sbin/ipset"
#IPSET_TYPE="bitmap:ip"
IPSET_TYPE="hash:net"
IPSET_OPTS="hashsize 16000 skbinfo counters"
BURST=10
QUANTUM=55140

if [ -f /etc/traffd/traffd-local ]; then
	. /etc/traffd/traffd-local 
fi

ACTION="$1" ; shift
ID_DST="$1" ; shift				# returned as hex number
ID_SRC="$1" ; shift				# returned as hex number
BW_DST="$1" ; shift
BW_SRC="$1" ; shift
MARK="0x${1}/0xFFFF" ; shift		# mark returned as HEX number
ADDR="$@"

add_addrs() {
	for addr in $@ ; do
		# ipv6 
		if [[ $addr =~ [:] ]]; then
			$IPSET add TRAFFD-SRC6 $addr skbprio 1:${ID_SRC} skbmark ${MARK}
			$IPSET add TRAFFD-DST6 $addr skbprio 1:${ID_DST} skbmark ${MARK}
		else 
			$IPSET add TRAFFD-SRC $addr skbprio 1:${ID_SRC} skbmark ${MARK}
			$IPSET add TRAFFD-DST $addr skbprio 1:${ID_DST} skbmark ${MARK}
		fi
	done
}

del_addrs() {
	for addr in $@ ; do
		# ipv6 
		if [[ $addr =~ [:] ]]; then
			$IPSET del TRAFFD-SRC6 $addr 
			$IPSET del TRAFFD-DST6 $addr 
		else 
			$IPSET del TRAFFD-SRC $addr 
			$IPSET del TRAFFD-DST $addr 
		fi
	done
}

case "$ACTION" in
	"ini") 
		$TC qdisc del dev $DEV root
		$TC qdisc add dev $DEV root handle 1:0 htb
		#$TC qdisc add dev $DEV root handle 1:0 hfsc default 1
		## hfsc drops unclasiffied traffic, the default class must be defined
		#$TC class add dev $DEV parent 1:0 classid 1:1 hfsc ls rate 5000000Kbit ul rate 5000000kbit

		$IPSET create TRAFFD-SRC $IPSET_TYPE $IPSET_OPTS
		$IPSET create TRAFFD-DST $IPSET_TYPE $IPSET_OPTS
		$IPSET create TRAFFD-SRC6 $IPSET_TYPE $IPSET_OPTS family inet6
		$IPSET create TRAFFD-DST6 $IPSET_TYPE $IPSET_OPTS family inet6
		exit 0
		;;

	"chk") 
		$IPTABLES  -C $CHAIN_SRC -t mangle -j SET --map-set TRAFFD-SRC src --map-prio --map-mark 2>/dev/null || \
			$IPTABLES  -A $CHAIN_SRC -t mangle -j SET --map-set TRAFFD-SRC src --map-prio --map-mark 
		$IPTABLES  -C $CHAIN_DST -t mangle -j SET --map-set TRAFFD-DST dst --map-prio --map-mark 2>/dev/null || \
			$IPTABLES  -A $CHAIN_DST -t mangle -j SET --map-set TRAFFD-DST dst --map-prio  --map-mark 
		$IP6TABLES  -C $CHAIN_SRC -t mangle -j SET --map-set TRAFFD-SRC6 src --map-prio --map-mark 2>/dev/null || \
			$IP6TABLES  -A $CHAIN_SRC -t mangle -j SET --map-set TRAFFD-SRC6 src --map-prio  --map-mark 
		$IP6TABLES  -C $CHAIN_DST -t mangle -j SET --map-set TRAFFD-DST6 dst --map-prio --map-mark 2>/dev/null || \
			$IP6TABLES  -A $CHAIN_DST -t mangle -j SET --map-set TRAFFD-DST6 dst --map-prio --map-mark
		;;

	"fin") 
		$IPTABLES  -F $CHAIN_SRC -t mangle 
		$IPTABLES  -F $CHAIN_DST -t mangle 
		$IP6TABLES  -F $CHAIN_SRC -t mangle 
		$IP6TABLES  -F $CHAIN_DST -t mangle 

		$TC qdisc del dev $DEV root

		$IPSET destroy TRAFFD-SRC
		$IPSET destroy TRAFFD-DST
		$IPSET destroy TRAFFD-SRC6
		$IPSET destroy TRAFFD-DST6
		;;

		
	"add") 
		add_addrs $ADDR 
		#$TC class add dev $DEV parent 1:0 classid 1:${ID_SRC} hfsc ls rate 500Kbit ul rate $BW_SRC 
		#$TC class add dev $DEV parent 1:0 classid 1:${ID_DST} hfsc ls rate 500Kbit ul rate $BW_DST 
		$TC class add dev $DEV parent 1:0 classid 1:${ID_SRC} htb rate $BW_SRC cburst $(($BW_SRC * $BURST))b quantum $QUANTUM
		$TC class add dev $DEV parent 1:0 classid 1:${ID_DST} htb rate $BW_DST cburst $(($BW_DST * $BURST))b quantum $QUANTUM
		$TC qdisc add dev $DEV parent 1:${ID_SRC} sfq perturb 10
		$TC qdisc add dev $DEV parent 1:${ID_DST} sfq perturb 10 
		;;

	"upd") 
		#$TC class change dev $DEV parent 1:0 classid 1:${ID_SRC} hfsc ls rate $BW_SRC ul rate $BW_SRC 
		#$TC class change dev $DEV parent 1:0 classid 1:${ID_DST} hfsc ls rate $BW_DST ul rate $BW_DST 
		$TC class change dev $DEV parent 1:0 classid 1:${ID_SRC} htb rate $BW_SRC burst $(($BW_SRC * $BURST)) quantum $QUANTUM
		$TC class change dev $DEV parent 1:0 classid 1:${ID_DST} htb rate $BW_DST burst $(($BW_DST * $BURST)) quantum $QUANTUM
		;;

	"del") 
		del_addrs $ADDR 
		$TC qdisc del dev $DEV parent 1:${ID_SRC} sfq 
		$TC qdisc del dev $DEV parent 1:${ID_DST} sfq  
		$TC class del dev $DEV parent 1:0 classid 1:${ID_SRC}  
		$TC class del dev $DEV parent 1:0 classid 1:${ID_DST} 
		;;

	"")
		echo "Unknown action"
		exit 0;
		;;
esac
