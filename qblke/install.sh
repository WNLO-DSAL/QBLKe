#!/bin/bash

nrchs=$(nvme lnvm id-ns /dev/nvme0n1 | grep "^ chnls" | awk '{print $3}')
nrluns=$(nvme lnvm id-ns /dev/nvme0n1 | grep "^ luns" | awk '{print $3}')
endlun=`echo ${nrchs}" * "${nrluns}" - 1" | bc`

# By default, use none scheduler for lightNVM.
if [[ $1 != "mq" ]];
then
	echo none > /sys/block/nvme0n1/queue/scheduler
fi

insmod qblk.ko
nvme lnvm create -d nvme0n1 -b 0 -e ${endlun} -n qblkdev -t qblk
