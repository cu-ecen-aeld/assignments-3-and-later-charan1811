#!/bin/bash
# A simple finder script

if [ $# -ne 2 ];
then
	echo "ERROR: Invalid number of arguments"
	echo "Total number of arguments: 2. usage: finder.sh <files dir> <search string>"
	exit 1
else
	if [ -d "$1" ];
	then
		TOTAL_FILES=$(find $1 -type f | wc -l)
		MATCHED_LINES=$(grep -r $2 $1 | wc -l)
		echo "The number of files are ${TOTAL_FILES} and the number of matching lines are ${MATCHED_LINES}"
		exit 0
	else
		echo "Input File directory does not exits"
		exit 1
	fi
fi
