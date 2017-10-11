#!/bin/bash

dir="/root/test"
tmp="/tmp/tmp1.txt"
tmp2="/tmp/tmp2.txt"

ls $dir > $tmp
ls $dir > $tmp2

START=1
END=$(cat $tmp | wc -l)

for (( i=$START; i<=$END; i++ ))
do
	cd $dir
	sed -i "${i}s/00${i}/S01E0${i}/" $tmp
	#awk "NR==$i { sub("00${i}", "S01E0${i}") }" $tmp
	before=$(sed -n "${i}p" < $tmp2)
	after=$(sed -n "${i}p" < $tmp)
	#echo `pwd`
	mv "$before" "$after"
done

rm $tmp $tmp2

exit 0
