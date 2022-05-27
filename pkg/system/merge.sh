#!/usr/local/bin/bash

echo "" > raw

for i in `ls 2*`; do
  echo "#FILE $i" >> raw
  cat $i >> raw

done
