#!/usr/bin/perl

# read files from raw, rename the files using a sequence
open(O, "raw");

$current = 0;
$count = 1;
%MAP = ();

while ($l = <O>) {
  if ($l =~ /#FILE (.+)-(.+)/) {
     $file = $1;
     if (!$MAP{$file}) {
         $MAP{$file} = $count;
         $count++;
     }
     $type = $2;
     close(W) if ($current);
     $current = sprintf("%-4.4d-%s", $MAP{$file}, $type);
     open(W, ">$current");
  } else {
     print W $l;
  }
}
close(W);


