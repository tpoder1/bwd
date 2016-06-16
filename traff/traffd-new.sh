#!/bin/bash 

#set -x

DEV="bond0"
CHAIN_SRC="FORWARD"
CHAIN_DST="FORWARD"
CHAIN_MARK="PREROUTING"
TC="/usr/sbin/tc"
IPTABLES="/usr/local/sbin/iptables"
IP6TABLES="/usr/local/sbin/ip6tables"
IPSET="/usr/local/sbin/ipset"
#IPSET_TYPE="bitmap:ip"
IPSET_TYPE="hash:net"
IPSET_OPTS="hashsize 16000 skbinfo counters"
BURST=10
HTB_OPTS="quantum 55140"
HFSC_OPTS="ls rate 1Mbit"

if [ -f /etc/traffd/traffd-local ]; then
	. /etc/traffd/traffd-local 
fi

ACTION="$1" ; shift
ID_DST="$1" ; shift				# returned as hex number
ID_SRC="$1" ; shift				# returned as hex number
PARENT_ID_DST="$1" ; shift		# returned as hex number
PARENT_ID_SRC="$1" ; shift		# returned as hex number
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
			$IPSET add TRAFFD-MARK6 $addr skbmark ${MARK}
		else 
			$IPSET add TRAFFD-SRC $addr skbprio 1:${ID_SRC} skbmark ${MARK}
			$IPSET add TRAFFD-DST $addr skbprio 1:${ID_DST} skbmark ${MARK}
			$IPSET add TRAFFD-MARK $addr skbmark ${MARK}
		fi
	done
}

del_addrs() {
	for addr in $@ ; do
		# ipv6 
		if [[ $addr =~ [:] ]]; then
			$IPSET del TRAFFD-SRC6 $addr 
			$IPSET del TRAFFD-DST6 $addr 
			$IPSET del TRAFFD-MARK6 $addr 
		else 
			$IPSET del TRAFFD-SRC $addr 
			$IPSET del TRAFFD-DST $addr 
			$IPSET del TRAFFD-MARK $addr 
		fi
	done
}

case "$ACTION" in
	"ini") 
		$TC qdisc del dev $DEV root
		#$TC qdisc add dev $DEV root handle 1:0 htb
		$TC qdisc add dev $DEV root handle 1:0 hfsc default 1
		## hfsc drops unclasiffied traffic, the default class must be defined
		$TC class add dev $DEV parent 1:0 classid 1:1 hfsc ul rate 5000000kbit $HFSC_OPTS

		$IPSET create TRAFFD-SRC $IPSET_TYPE $IPSET_OPTS
		$IPSET create TRAFFD-DST $IPSET_TYPE $IPSET_OPTS
		$IPSET create TRAFFD-MARK $IPSET_TYPE $IPSET_OPTS
		$IPSET create TRAFFD-SRC6 $IPSET_TYPE $IPSET_OPTS family inet6
		$IPSET create TRAFFD-DST6 $IPSET_TYPE $IPSET_OPTS family inet6
		$IPSET create TRAFFD-MARK6 $IPSET_TYPE $IPSET_OPTS family inet6
		exit 0
		;;

	"chk") 
		$IPTABLES  -C $CHAIN_SRC -t mangle -j SET --map-set TRAFFD-SRC src --map-prio --map-mark 2>/dev/null || \
			$IPTABLES  -A $CHAIN_SRC -t mangle -j SET --map-set TRAFFD-SRC src --map-prio --map-mark 
		$IPTABLES  -C $CHAIN_DST -t mangle -j SET --map-set TRAFFD-DST dst --map-prio --map-mark 2>/dev/null || \
			$IPTABLES  -A $CHAIN_DST -t mangle -j SET --map-set TRAFFD-DST dst --map-prio  --map-mark 
		$IPTABLES  -C $CHAIN_MARK -t mangle -j SET --map-set TRAFFD-MARK src,dst --map-mark 2>/dev/null || \
			$IPTABLES  -A $CHAIN_MARK -t mangle -j SET --map-set TRAFFD-MARK src,dst --map-mark 

		$IP6TABLES  -C $CHAIN_SRC -t mangle -j SET --map-set TRAFFD-SRC6 src --map-prio --map-mark 2>/dev/null || \
			$IP6TABLES  -A $CHAIN_SRC -t mangle -j SET --map-set TRAFFD-SRC6 src --map-prio  --map-mark 
		$IP6TABLES  -C $CHAIN_DST -t mangle -j SET --map-set TRAFFD-DST6 dst --map-prio --map-mark 2>/dev/null || \
			$IP6TABLES  -A $CHAIN_DST -t mangle -j SET --map-set TRAFFD-DST6 dst --map-prio --map-mark
		$IP6TABLES  -C $CHAIN_MARK -t mangle -j SET --map-set TRAFFD-MARK6 src,dst --map-mark 2>/dev/null || \
			$IP6TABLES  -A $CHAIN_MARK -t mangle -j SET --map-set TRAFFD-MARK6 src,dst --map-mark
		;;

	"fin") 
		$IPTABLES  -F $CHAIN_SRC -t mangle 
		$IPTABLES  -F $CHAIN_DST -t mangle 
		$IPTABLES  -F $CHAIN_MARK -t mangle 
		$IP6TABLES  -F $CHAIN_SRC -t mangle 
		$IP6TABLES  -F $CHAIN_DST -t mangle 
		$IP6TABLES  -F $CHAIN_MARK -t mangle 

		$TC qdisc del dev $DEV root

		$IPSET destroy TRAFFD-SRC
		$IPSET destroy TRAFFD-DST
		$IPSET destroy TRAFFD-MARK
		$IPSET destroy TRAFFD-SRC6
		$IPSET destroy TRAFFD-DST6
		$IPSET destroy TRAFFD-MARK6
		;;

		
	"add") 
		add_addrs $ADDR 
		$TC class add dev $DEV parent 1:${PARENT_ID_SRC} classid 1:${ID_SRC} hfsc ul rate $BW_SRC $HFSC_OPTS
		$TC class add dev $DEV parent 1:${PARENT_ID_DST} classid 1:${ID_DST} hfsc ul rate $BW_DST $HFSC_OPTS
		#$TC class add dev $DEV parent 1:0 classid 1:${ID_SRC} htb rate $BW_SRC cburst $(($BW_SRC * $BURST))b $HTB_OPTS
		#$TC class add dev $DEV parent 1:0 classid 1:${ID_DST} htb rate $BW_DST cburst $(($BW_DST * $BURST))b $HTB_OPTS
		$TC qdisc add dev $DEV parent 1:${ID_SRC} sfq perturb 60
		$TC qdisc add dev $DEV parent 1:${ID_DST} sfq perturb 60 
		;;

	"upd") 
		$TC class change dev $DEV parent 1:${PARENT_ID_SRC} classid 1:${ID_SRC} hfsc ul rate $BW_SRC $HFSC_OPTS
		$TC class change dev $DEV parent 1:${PARENT_ID_DST} classid 1:${ID_DST} hfsc ul rate $BW_DST $HFSC_OPTS
		#$TC class change dev $DEV parent 1:0 classid 1:${ID_SRC} htb rate $BW_SRC burst $(($BW_SRC * $BURST)) $HTB_OPTS
		#$TC class change dev $DEV parent 1:0 classid 1:${ID_DST} htb rate $BW_DST burst $(($BW_DST * $BURST)) $HTB_OPTS
		;;

	"del") 
		del_addrs $ADDR 
		$TC qdisc del dev $DEV parent 1:${ID_SRC} sfq 
		$TC qdisc del dev $DEV parent 1:${ID_DST} sfq  
		$TC class del dev $DEV parent 1:${PARENT_ID_SRC} classid 1:${ID_SRC}  
		$TC class del dev $DEV parent 1:${PARENT_ID_DST} classid 1:${ID_DST} 
		;;

	"")
		echo "Unknown action"
		exit 0;
		;;
esac
