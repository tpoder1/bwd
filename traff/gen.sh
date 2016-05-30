
x=1 

while [ $x -lt 255 ]; do 
	echo "#@shaper rule ip=100.100.103.${x} download=T1D upload=T1U mark=20" 
	x=$(($x + 1))
done

