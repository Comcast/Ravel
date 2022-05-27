#!/usr/local/bin/bash


for i in `ls 0* | cut -d- -f1 | sort | uniq`; do
  if test "$i" != "raw"; then
    echo "I=$i"
    sort $i-newrules > x1
    sort $i-newrulesEarly.test $i-newrulesLate.test  > x2
    diff x1 x2
  fi
done

exit 0
