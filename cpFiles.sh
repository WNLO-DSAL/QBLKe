#!/bin/bash

path=$1
kernelSource=/usr/src/kernels/linux
files=`ls $path`

for filename in $files
do
	if [[ $filename != cpFiles.sh && $filename != qblke ]]
	then
		echo cp -r $filename $kernelSource/
		yes | cp -r $filename $kernelSource/ 2>/dev/null
	fi
done
