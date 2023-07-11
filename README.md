# Perl SHA-3 Stream Cipher (SSC)

## Usage

###To test AES encryption (which is used in encrypting the SSC key):

perl -I. key\_encrypt\_main.pl -e|-d key\_file received

Where -e is encrypt and -d is decrypt. Only one mode can be selected
at a time.

###To run the SSC encryption:

To encrypt:

perl ssc.pl input.plain  output.cipher

To decrypt:

perl ssc.pl input.cipher output.plain key\_file

NOTE: You will be prompted for a non-echoed key password which is not
      saved.

##Author
Roger Doss
