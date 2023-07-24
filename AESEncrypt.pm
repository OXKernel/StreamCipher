#!/usr/bin/perl
#
# Copyright (C) 2023. Roger Doss. All Rights Reserved.
# Provided under MIT License.
#
# @description:
#
#   Perl module to use AES to encrypt arbitrary data. Expects
#   a password of 16, 24, or 32 bytes. Pads data using random
#   ascii characters starting from 'A' to 'Z'. Includes
#   a header which tells us the actual size of the plaintext,
#   and uses this information to decrypt.
#
# @references:
#
# [1] https://stackoverflow.com/questions/39801195/how-can-perl-prompt-for-a-password-without-showing-it-in-the-terminal
#
# [2] https://metacpan.org/pod/Crypt::Cipher::AES
#
# @author:
#   Roger Doss
#
package AESEncrypt;
use Moose;
use Crypt::Cipher::AES;

my $SIZE_LEN = 20;

sub read_file {
  my $self = shift;
  my $filename = shift;
  open my $fh, '<', $filename or die "Can't open file $!";
  binmode($fh);
  read $fh, my $file_content, -s $fh;
  close $fh;
  return $file_content;
}

sub write_file {
  my $self = shift;
  my $filename = shift;
  my $data = shift;
  open my $fh, '>', $filename or die "Can't open file $!";
  binmode($fh);
  print $fh $data;
  close $fh;
}

sub prompt_for_password {
    require Term::ReadKey;
    my $self = shift;
    my $prompt = shift;

    # The terminal should not echo characters.
    Term::ReadKey::ReadMode('noecho');

    print $prompt;
    my $password = Term::ReadKey::ReadLine(0);

    # Reset the terminal to it's prior state.
    Term::ReadKey::ReadMode('restore');

    print "\n";

    # remove line endings.
    $password =~ s/\R\z//;

    return $password;
}

sub pad_data {
  my $self = shift;
  my $plaintext = shift;
  # Pad the plaintext to make multiple of 16 bytes.
  if(length($plaintext) % 16) {
    my $currentLen = length($plaintext);
    my $curr = int($currentLen / 16);
    $curr++;
    $curr *= 16;
    for(my $i = 0; $i < ($curr - $currentLen); ++$i) {
      #print "padding...$i \n";
      # Get random, non-negative integer.
      my $r = int(rand());
      if($r <= 0) {
        $r *= -1;
        $r++;
      }
      $plaintext .= ($r % 26) + 65; # Add to ascii 'A' to get random all caps alphabet.
    }
  }
  return $plaintext;
}

sub encrypt {
  my $self = shift;
  # must be 16 bytes or multiple of 16 bytes.
  my $plaintext = shift;
  my $password = prompt_for_password($self, "Enter password: ");
  my $password2 = prompt_for_password($self, "Re-Enter password: ");

  if($password ne $password2) {
    print "passwords don't match\n";
    exit(0);
  }

  my $len = length($plaintext);
  $plaintext = pad_data($self, $plaintext);
  my $len2 = length($plaintext);
  # password must be 16 bytes, 24, or 32
  my $password_len = length($password);
  if(!($password_len == 16 or $password_len == 24 or $password_len == 32)) {
    print "error password must be of length 16, 24, or 32, received [$password_len]\n";
    exit(0);
  }
  my $cipher = Crypt::Cipher::AES->new($password);
  #print "key=",$cipher->keysize,"\n";
  my $blocks = int($len2 / 16);
  my $ciphertext = "";
  my $start = 0;
  # Encrypt in chunks of 16 bytes.
  for(my $i = 0; $i < $blocks; ++$i) {
   $ciphertext .= $cipher->encrypt(substr($plaintext, $start, 16));
   $start = ($i + 1) * 16;
  }
  $ciphertext = sprintf("%20d", $len) . $ciphertext; # Write out actual size header plus padded text.
  return $ciphertext;
}

sub decrypt {
  my $self = shift;
  # must be 16 bytes or multiple of 16 bytes.
  my $ciphertext = shift;
  my $password = prompt_for_password($self, "Enter password: ");
  my $password2 = prompt_for_password($self, "Re-Enter password: ");

  if($password ne $password2) {
    print "passwords don't match\n";
    exit(0);
  }

  # Extract actual size header.
  my $len = int(substr($ciphertext, 0, $SIZE_LEN));
  # Get only the cipher text.
  $ciphertext = substr($ciphertext, $SIZE_LEN, length($ciphertext) - $SIZE_LEN);
  my $len2 = int($len / 16);
  if($len % 16) {
    $len2++;
    $len2 *= 16;
  } else {
    $len2 = $len;
  }
  # Should be multiple of 32 as prior padding was applied.

  # password must be 16 bytes, 24, or 32
  my $password_len = length($password);
  if(!($password_len == 16 or $password_len == 24 or $password_len == 32)) {
    print "error password must be of length 16, 24, or 32, received [$password_len]\n";
    exit(0);
  }
  my $cipher = Crypt::Cipher::AES->new($password);
  #print "key=",$cipher->keysize,"\n";
  my $blocks = int($len2 / 16);
  my $plaintext = "";
  my $start = 0;
  for(my $i = 0; $i < $blocks; ++$i) {
   $plaintext .= $cipher->decrypt(substr($ciphertext, $start, 16));
   $start = ($i + 1) * 16;
  }
  # Remove padding.
  $plaintext = substr($plaintext, 0, $len);
  return $plaintext;
}

1;
