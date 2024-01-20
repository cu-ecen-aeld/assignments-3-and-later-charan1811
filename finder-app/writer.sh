#!/bin/bash
# A simple writer script

if [ "$#" -gt 0 ] && [ "$#" -lt 3 ];
then
	if [ -f "$1" ];
	then
		echo $2 > $1
	else
		if [ -d "$(dirname "$1")" ];
		then
			touch $1
			echo $2 > $1
		else
			echo "Input file is not present, creating new file at $1"
			mkdir -p "$(dirname "$1")"
			touch $1
			echo $2 > $1
		fi
	fi
else
	echo "Please provide valid arguments"
	exit 1;
fi
