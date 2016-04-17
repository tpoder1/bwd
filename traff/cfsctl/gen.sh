
i=1
j=10

while [ $i -lt 100 ]; do 

	(while [ $j -lt 100 ]; do 

		echo "100.64.$i.$j"

		echo "	#@shaper rule ip=147.229.$i.$j download=%E2U upload=%E2D active=yes"
		j=$(($j + 1))
	done)

	i=$(($i + 1))
done
