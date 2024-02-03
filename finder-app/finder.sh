#!/bin/sh
# Author: Sai Charan Mandadi
# Description: Finds the required string in the given input directories and prints the count of total
#number of files and matched lines.

#Check if the arguments are valid number of arguments
if [ $# -ne 2 ];
then
	echo "ERROR: Invalid number of arguments"
	echo "Total number of arguments: 2. usage: finder.sh <files dir> <search string>"
	exit 1
else
#Checks if the input file directory exists and then extracts the total files and matched lines with the input string.
	if [ -d "$1" ];
	then
		TOTAL_FILES=$(find $1 -type f | wc -l)
		MATCHED_LINES=$(grep -r $2 $1 | wc -l)
		echo "The number of files are ${TOTAL_FILES} and the number of matching lines are ${MATCHED_LINES}"
		exit 0
#Handles the condition where the input file directory is not present.
	else
		echo "Input File directory does not exits"
		exit 1
	fi
fi
