#!/usr/bin/perl
#
# Copyright (C) 2023. Roger Doss. All Rights Reserved.
# Provided under MIT License.
#
# @description:
#
# Implements a stream cipher I am calling ssc which 
# is loosly based on rc4. It stands for
# SHA-3 Stream Cipher.
#
# It's a stream cipher using real random numbers as a seed from
# random.org to encrypt with SHA-3 as the pseudo-random
# number generator which generates a stream to use for
# encrypting/decrypting byte by byte using XOR operation.
#
# @author:
#
# Roger Doss
#
package SSC;
use Moose;

use AESEncrypt;

use Digest::SHA3 qw(sha3_256_hex);
use LWP::Simple;

#
# get_key
# 
# returns numbers array obtained from random.org as an array ref
#
sub get_key {
  my $self = shift;
  my @numbers = ();
  my $url = 'https://www.random.org/integers/?num=10&min=1&max=65536&col=1&base=10&format=plain&rnd=new';
  my $content = get $url;
  die "Couldn't get $url" unless defined $content;

  chomp $content;
  @numbers = split ' ', $content;
  return \@numbers;
}

#
# get_key_from_file
# 
# @param key_file_name (contains encryption key)
#
# returns numbers array read from file as an array ref
#
sub get_key_from_file {
  my $self = shift;
  my $key_file = shift;
  my @numbers = ();
  # Read in the encrypted key file, and decrypt it.
  my $ke = AESEncrypt->new;
  my $keyin = $ke->read_file($key_file);
  my $plaintext = $ke->decrypt($keyin);
  @numbers = split ' ', $plaintext;
  return \@numbers;
}

#
# save_key:
#
# @param key_file_name
# @param key (as integer array)
#
# @output key_file_name.ssc.key
#
sub save_key {
  my $self = shift;
  my $key_file_name=shift . ".ssc.key";
  my $numbers_ref= shift; # De-reference array ref to array.
  my @numbers = @{$numbers_ref};
  my $ke = AESEncrypt->new;
  my $keyout = "";
  for (my $i=0; $i <= $#numbers; $i++) {
    # Build string with key in it using integers separated by space.
    $keyout .= sprintf("%d ", $numbers[$i]);
  }
  # Encrypt, and write to disk.
  my $ciphertext = $ke->encrypt($keyout);
  $ke->write_file($key_file_name, $ciphertext);
}

#
# cipher:
#
# @param mode (-e => encrypt, -d => decrypt)
# @param key array
# @param input_file_name
# @param output_file_name
#
# @output cipher or plain text depending on mode written in output_file_name
#
sub cipher {
   my $self = shift;
   my $ENCRYPT="-e";
   my $DECRYPT="-d";
   my $mode = shift;
   my $numbers_ref = shift; # De-reference array ref to array.
   my @numbers = @{$numbers_ref};
   my $key = "";
   my $num = "";
   for (my $i=0; $i <= $#numbers; $i++) {
     #print $numbers[$i],"\t";
     $key = $key . $numbers[$i];
   }

   # [1] Call SHA-3 a fixed number of times in a loop
   # [2] Read input file into string
   # [3] Loop for i=0 to n-1, xor byte with the key, if we run out of digest bytes,
   #     do another round of SHA-3 to get more bytes, continue till done.
   my $digest = "";
   my $ROUNDS = 16;
   
   $digest = sha3_256_hex($key);
   for(my $i=0; $i < $ROUNDS; $i++) {
     $digest = sha3_256_hex($digest);
   }
   
   my $input_file=shift;
   my $output_file=shift;
   print "in=$input_file\nout=$output_file\n";
   open my $fh, '<', $input_file or die "Can't open input file $!";
   binmode($fh);
   read $fh, my $file_content, -s $fh;
   
   my $char  = "";
   my $kchar = "";
   my $char2 = "";
   my $count = 0;
   my $dlen  = length $digest;
   
   open my $out, '>', $output_file or die "Can't open output file $!";
   binmode($out);
   
   my $len = -s $fh;
   
   if($mode eq $ENCRYPT) {
     print $out $len; # Output header when encrypting.
     print $out ':';
   }
   
   my $i = 0;
   
   if($mode eq $DECRYPT) {
     seek $fh, 0, 0; # rewind
     $num = "";
     for($i=0; $i <= -s $fh; $i++) {
       $char = substr($file_content, $i, 1);
       if($char eq ':') {
         last;
       }
       $num  = $num . $char;
     }
     $len = int($num);
     $len += $i; # Account for header length.
     $i++; # Skip to start of encrypted data.
   }
   
   #print "\n",$digest,"\n";
   #print "\n~~\n";
   #print $file_content,"\n";
   
   # Encrypt/Decrypt loop.
   for(; $i <= $len; $i++) {
     $char  = substr($file_content, $i, 1); # Read char from string.
     $kchar = substr($digest, $count, 1);   # Read char from digest.
     my $cipher = $char ^ $kchar;  # Encrypt using XOR.
     #print "$i\n";
     #print "$count\n";
     #print "$kchar:$char:$cipher\n";
     print $out $cipher;
     $count++;
     if($count >= $dlen) {
       # Get more pseudo-rand bits.
       $digest = sha3_256_hex($digest);
       $count  = 0;
     }
   }
   
   close $out;
   close $fh;
}

1;
