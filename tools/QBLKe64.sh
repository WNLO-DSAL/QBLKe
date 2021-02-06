#!/bin/bash

# QBLKe64.sh is a startup script example.
# Before running the script, you may need to change the following parts:
# 1. FEMU binary path.
# 2. CPU, memory, OCSSD capacity, etc.
# 2. Network configurations.


runner=`whoami`

if [ $runner != "root" ]
then
	echo "Must be root"
	exit
fi

/mnt/sdc/qhw/FEMU/build-femu/x86_64-softmmu/qemu-system-x86_64 \
	-name "QBLKe64" \
	-m 8G \
	-smp 32 \
	--enable-kvm \
	-device virtio-scsi-pci,id=scsi0 \
	-drive file=./QBLKeImage.qcow2,index=0,media=disk,format=qcow2,discard=on \
	-device femu,devsz_mb=65536,namespaces=1,lmetasize=16,nlbaf=5,lba_index=3,mdts=10,lnum_ch=32,lnum_lun=4,lnum_pln=2,lsec_size=4096,lsecs_per_pg=4,lpgs_per_blk=512,femu_mode=0 \
	-qmp unix:./qmp-sock,server,nowait \
	-k en-us \
	-cpu host \
	-mem-prealloc \
	-display sdl

