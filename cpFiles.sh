#!/bin/bash

path=kernel_patch
kernelSource=/usr/src/kernels/linux
files=`ls $path`

for filename in $files
do
	echo cp -r kernel_patch/$filename $kernelSource/
	yes | cp -r kernel_patch/$filename $kernelSource/
done
