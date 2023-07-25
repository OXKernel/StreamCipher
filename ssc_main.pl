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
