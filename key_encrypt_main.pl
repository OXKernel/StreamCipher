#!/usr/bin/perl
# Copyright (C) 2023. Roger Doss. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
use AESEncrypt;
package main;

if ($#ARGV != 1) {
  print "syntax: perl -I. key_encrypt_main.pl -e|-d key_file received $#ARGV params\n";
  exit(0);
}

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
