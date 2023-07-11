#!/usr/bin/perl
use AESEncrypt;
package main;

if ($#ARGV != 1) {
  print "syntax: perl -I. key_encrypt_main.pl -e|-d key_file received $#ARGV params\n";
  exit(0);
}

#print "$ARGV[0] $ARGV[1]\n";

my $ke = AESEncrypt->new;

if ($ARGV[0] eq "-e") {
  my $key = $ke->read_file($ARGV[1]);
  my $ciphertext = $ke->encrypt($key);
  $ke->write_file($ARGV[1]."out", $ciphertext);
} elsif ($ARGV[0] eq "-d") {
  my $key = $ke->read_file($ARGV[1]);
  my $plaintext = $ke->decrypt($key);
  print "$plaintext\n";
}
