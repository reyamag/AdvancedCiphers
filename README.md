# AdvancedCiphers
A program written in C++ that implements DES & AES ecnryption/decryption on blocks of text.

# Authors
Charles Bucher: charles.abucher@gmail.com <br>
Reyniel Maglian: rrmaglian@csu.fullerton.edu

# Instructions

1. *Setup<br>*
Ensure openssl is a library installed on your machine with support for c++11

2. *Compile & Build*<br>
Run: `make clean`<br>
Run: `make`

3. *Execute*<br>
***./cipher <CIPHER_NAME> \<KEY> <ENC/DEC> <INPUT_FILE> <OUTPUT_FILE>***

# Argument Descriptions

<CIPHER_NAME>:
- DES
- AES

\<KEY>:
- The key that the encryption/decryption algorithm will use
- Valid DES keys: 16 characters representing a 64-bit hexadecimal number
- Valid AES keys: 16 characters representing a 128-bit number

<ENC/DEC>:
- To decrypt, or encrypt, respectively

<INPUT_FILE>:
- The file whose contents will be encrypted /decrypted.

<OUTPUT_FILE>:
- The file that will be outputed with the encrypted/decrypted code.

# Additional

No extra credit implemented or special considerations.
