#!/bin/bash

path=kernel_patch
kernelSource=/usr/src/kernels/linux
files=`ls $path`

for filename in $files
do
	echo cp -r $filename $kernelSource/
	yes | cp -r $filename $kernelSource/ 2>/dev/null
done
