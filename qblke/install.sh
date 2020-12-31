#!/bin/bash

# By default, use none scheduler for lightNVM.
if [[ $1 != "mq" ]];
then
	echo none > /sys/block/nvme0n1/queue/scheduler
fi

insmod qblk.ko
nvme lnvm create -d nvme0n1 -b 0 -e 127 -n qblkdev -t qblk
