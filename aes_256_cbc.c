/*
When a 128-bit key is used, implementations MUST use 10 rounds.  
When a 192-bit key is used, implementations MUST use 12 rounds.  
When a 256-bit key is used, implementations MUST use 14 rounds.


The AES uses a block size of sixteen octets (128 bits).

   Padding is required by the AES to maintain a 16-octet (128-bit)
   blocksize.  Padding MUST be added, as specified in [ESP], such that
   the data to be encrypted (which includes the ESP Pad Length and Next
   Header fields) has a length that is a multiple of 16 octets.

   
*/
