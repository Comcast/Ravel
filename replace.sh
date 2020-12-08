#!/bin/bash

find . -type f | while read FILE; do
	echo -- $FILE;
	sed -e 's/\/comcast\/sirupsen\//\/Comcast\/sirupsen\//g' $FILE
done
