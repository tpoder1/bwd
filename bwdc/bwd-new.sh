#!/bin/bash 

#set -x

DEV="eth8.20"
LOG="/tmp/bwd.log"
CHAIN="FORWARD"
#QDISC="hfsc"
QDISC="htb"
ACTION="$1"
ID="$2"

# new rule 
if [ "$ACTION" == "new" ]; then

	#test root rule 
#	if [ "$(tc qdisc show dev $DEV | grep $QDISC)" == "" ]; then 
#		tc qdisc add dev $DEV root handle 1:0 $QDISC
#	fi

	# shaping rule 
	while read line ; do
		KEY=$(echo $line | cut -f1 -d:)
		VAL=$(echo $line | cut -f2 -d:)

		case "$KEY" in
			"limit_bps") 
				echo "LIMIT $VAL $ID" >> $LOG
				tc class add dev $DEV parent 1:0 classid 1:${ID} $QDISC rate $VAL burst $VAL # 8 secs 
				;;
			"srcip") 
				echo "SRCIP $VAL $ID" >> $LOG
				iptables -A $CHAIN -s $VAL -j CLASSIFY --set-class 1:${ID}
				;;
			"dstip") 
				echo "DSTIP $VAL $ID" >> $LOG
				iptables -A $CHAIN -d $VAL -j CLASSIFY --set-class 1:${ID}
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
			"srcip") 
				echo "SRCIP $VAL $ID" >> $LOG
				iptables -D $CHAIN -s $VAL -j CLASSIFY --set-class 1:${ID}
				;;
			"dstip") 
				echo "DSTIP $VAL $ID" >> $LOG
				iptables -D $CHAIN -d $VAL -j CLASSIFY --set-class 1:${ID}
				;;
			"")
				exit 0;
				;;
		esac

	done
	echo "DEL $ID" >> $LOG
fi

