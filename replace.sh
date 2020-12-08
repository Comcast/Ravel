#!/bin/bash

find . -type f | while read FILE; do
	echo "-- $FILE"
	sed -i '' 's/\/comcast\/ravel/\/Comcast\/Ravel/g' $FILE
done
