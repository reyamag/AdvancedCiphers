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

# LICENSE:

Copyright 2018 Reyniel Maglian & Charles Bucher

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
