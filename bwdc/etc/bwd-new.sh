#!/bin/bash 

#set -x

DEV="eth2"
LOG="/var/log/bwd-rules.log"
CHAIN="FORWARD"
QDISC="htb"
ACTION="$1"
ID="$2"

date >> $LOG

# new rule 
if [ "$ACTION" == "new" ]; then

	#test root rule 
	if [ "$(tc qdisc show dev $DEV | grep $QDISC)" == "" ]; then 
		tc qdisc add dev $DEV root handle 1:0 $QDISC
	fi

	# shaping rule 
	while read line ; do
		KEY=$(echo $line | cut -f1 -d:)
		VAL=$(echo $line | cut -f2 -d:)

		case "$KEY" in
			"limit_bps") 
				echo "ADD LIMIT $VAL $ID" >> $LOG
				tc class add dev $DEV parent 1:0 classid 1:${ID} $QDISC rate $VAL burst 0 quantum 1514
				;;
			"srcip4") 
				echo "ADD SRCIP $VAL $ID" >> $LOG
				#iptables -A $CHAIN -t mangle -s $VAL -j CLASSIFY --set-class 1:${ID}
				ipset add BWD-SRC $VAL skbprio 1:${ID}
				;;
			"srcip6") 
				echo "ADD SRCIP $VAL $ID" >> $LOG
				ip6tables -A $CHAIN -t mangle -s $VAL -j CLASSIFY --set-class 1:${ID}
				;;
			"dstip4") 
				echo "ADD DSTIP $VAL $ID" >> $LOG
				#iptables -A $CHAIN -t mangle -d $VAL -j CLASSIFY --set-class 1:${ID}
				ipset add BWD-DST $VAL skbprio 1:${ID}
				;;
			"dstip6") 
				echo "ADD DSTIP $VAL $ID" >> $LOG
				ip6tables -A $CHAIN -t mangle -d $VAL -j CLASSIFY --set-class 1:${ID}
				;;
			"")
				exit 0;
				;;
		esac

	done

fi



# delete rule
if [ "$ACTION" == "del" ]; then

	# shaping rule 
	while read line ; do
		KEY=$(echo $line | cut -f1 -d:)
		VAL=$(echo $line | cut -f2 -d:)

		case "$KEY" in
			"limit_bps") 
				echo "DEL LIMIT $VAL $ID" >> $LOG
				tc class del dev $DEV parent 1:0 classid 1:${ID}
				;;
			"srcip4") 
				echo "DEL SRCIP $VAL $ID" >> $LOG
				iptables -D $CHAIN -t mangle -s $VAL -j CLASSIFY --set-class 1:${ID}
				;;
			"srcip6") 
				echo "DEL SRCIP $VAL $ID" >> $LOG
				ip6tables -D $CHAIN -t mangle -s $VAL -j CLASSIFY --set-class 1:${ID}
				;;
			"dstip4") 
				echo "DEL DSTIP $VAL $ID" >> $LOG
				iptables -D $CHAIN -t mangle -d $VAL -j CLASSIFY --set-class 1:${ID}
				;;
			"dstip6") 
				echo "DEL DSTIP $VAL $ID" >> $LOG
				ip6tables -D $CHAIN -t mangle -d $VAL -j CLASSIFY --set-class 1:${ID}
				;;
			"")
				exit 0;
				;;
		esac

	done
	echo "DEL $ID" >> $LOG
fi

