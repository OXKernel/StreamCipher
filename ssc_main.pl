#!/usr/bin/perl
# Copyright (C) 2023. Roger Doss. All Rights Reserved.
# Provided under MIT License.
use SSC;
package main;

if ($#ARGV < 1 or $#ARGV > 3) {
  print "syntax: perl ssc.pl input.plain  output.cipher\n";
  print "syntax: perl ssc.pl input.cipher output.plain key_file\n";
  exit(0);
}

my $ssc = SSC->new;

if ($#ARGV == 2) {
  # decrypt
  my $key = $ssc->get_key_from_file($ARGV[2]);
  $ssc->cipher("-d", $key, $ARGV[0], $ARGV[1]);
} elsif ($#ARGV == 1) {
  # encrypt
  my $key = $ssc->get_key();
  $ssc->cipher("-e", $key, $ARGV[0], $ARGV[1]);
  $ssc->save_key($ARGV[1], $key);
}
