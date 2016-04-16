#!/bin/bash 

#set -x

DEV="bond0"
CHAIN="FORWARD"
QDISC="htb"
IPTABLES="/usr/local/sbin/iptables"
IP6TABLES="/usr/local/sbin/ip6tables"
TC="/usr/sbin/tc"
IPSET="/usr/local/sbin/ipset"
IPSET_TYPE="hash:net"
IPSET_OPTS="skbinfo counters"
BURST=8

ACTION="$1" ; shift
ID_SRC="$1" ; shift
ID_DST="$1" ; shift
BW_SRC="$1" ; shift
BW_DST="$1" ; shift
ADDR="$@"

add_addrs() {
	for addr in $@ ; do
		# ipv6 
		if [[ $addr =~ [:] ]]; then
			$IPSET add BWD-SRC6 $addr skbprio 1:${ID_SRC}
			$IPSET add BWD-DST6 $addr skbprio 1:${ID_DST}
		else 
			$IPSET add BWD-SRC $addr skbprio 1:${ID_SRC}
			$IPSET add BWD-DST $addr skbprio 1:${ID_DST}
		fi
	done
}

del_addrs() {
	for addr in $@ ; do
		# ipv6 
		if [[ $addr =~ [:] ]]; then
			$IPSET del BWD-SRC6 $addr 
			$IPSET del BWD-DST6 $addr 
		else 
			$IPSET del BWD-SRC $addr 
			$IPSET del BWD-DST $addr 
		fi
	done
}

case "$ACTION" in
	"ini") 
		$TC qdisc del dev $DEV root
		$TC qdisc add dev $DEV root handle 1:0 htb

		$IPSET create BWD-SRC $IPSET_TYPE $IPSET_OPTS
		$IPSET create BWD-DST $IPSET_TYPE $IPSET_OPTS
		$IPSET create BWD-SRC6 $IPSET_TYPE $IPSET_OPTS family inet6
		$IPSET create BWD-DST6 $IPSET_TYPE $IPSET_OPTS family inet6
		exit 0
		;;

	"chk") 
		$IPTABLES  -C $CHAIN -t mangle -j SET --map-set BWD-SRC src --map-prio 2>/dev/null || \
			$IPTABLES  -A $CHAIN -t mangle -j SET --map-set BWD-SRC src --map-prio 
		$IPTABLES  -C $CHAIN -t mangle -j SET --map-set BWD-DST dst --map-prio 2>/dev/null || \
			$IPTABLES  -A $CHAIN -t mangle -j SET --map-set BWD-DST dst --map-prio 
		$IP6TABLES  -C $CHAIN -t mangle -j SET --map-set BWD-SRC6 src --map-prio 2>/dev/null || \
			$IP6TABLES  -A $CHAIN -t mangle -j SET --map-set BWD-SRC6 src --map-prio 
		$IP6TABLES  -C $CHAIN -t mangle -j SET --map-set BWD-DST6 dst --map-prio 2>/dev/null || \
			$IP6TABLES  -A $CHAIN -t mangle -j SET --map-set BWD-DST6 dst --map-prio 
		;;

	"fin") 
		$IPTABLES  -F $CHAIN -t mangle 
		$IP6TABLES  -F $CHAIN -t mangle 

		$TC qdisc del dev $DEV root
		$TC qdisc add dev $DEV root handle 1:0 $QDISC

		$IPSET destroy BWD-SRC
		$IPSET destroy BWD-DST
		$IPSET destroy BWD-SRC6
		$IPSET destroy BWD-DST6
		;;

		
	"add") 
		add_addrs $ADDR 
		$TC class add dev $DEV parent 1:0 classid 1:${ID_SRC} $QDISC rate $BW_SRC burst $BW_SRC 
		$TC class add dev $DEV parent 1:0 classid 1:${ID_DST} $QDISC rate $BW_DST burst $BW_DST
		;;

	"upd") 
		$TC class change dev $DEV parent 1:0 classid 1:${ID_SRC} $QDISC rate $BW_SRC burst $BW_SRC 
		$TC class change dev $DEV parent 1:0 classid 1:${ID_DST} $QDISC rate $BW_DST burst $BW_DST
		;;

	"del") 
		del_addrs $ADDR 
		$TC class del dev $DEV parent 1:0 classid 1:${ID_SRC}  
		$TC class del dev $DEV parent 1:0 classid 1:${ID_DST} 
		;;

	"")
		echo "Unknown action"
		exit 0;
		;;
esac
