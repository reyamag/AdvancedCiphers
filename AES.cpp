#include "AES.h"
#include <string>
#include <iostream>
#include <stdio.h>
#include <openssl/aes.h>

using std::cout;
using std::endl;

typedef unsigned char uchar;

/**
 * Sets the key to use
 * @param key - the first byte of this represents whether
 * to encrypt or to decrypt. 00 means encrypt and any other
 * value to decrypt.  Then come the bytes of the 128-bit key
 * (should be 16 of them).
 * @return - True if the key is valid and False otherwise
 */
bool AES::setKey(const uchar* keyArray)
{
	
	// TODO: AES implementation of openssl cares about whether
	// you are encrypting or decrypting when setting the key.
	// That is, when encrypting you use function AES_set_encrypt_key(...)
	// and when decrypting AES_set_decrypt_key(...).
	//
	// One way to solve this problem is to pass in a 17 byte key, where
	// the first byte is used to indicate whether we are encrypting or
	// decrypting. E.g., if the first byte is 0, then use AES_set_encrypt_key(...).
	// Otherwise, use AES_set_decrypt_key(...).  The rest of the bytes in the
	// array indicate the 16 bytes of the 128-bit AES key.
	//
	// Both functions return 0 on success and other values on faliure.
	// For documentation, please see https://boringssl.googlesource.com/boringssl/+/2623/include/openssl/aes.h
	// and aes.cpp example provided with the assignment.

    // Update class key
    memcpy(aes_key, keyArray+1, 16);
	
	//Checking for the first byte to see if the key is going to be used for 
	//encrpytion or decrpyption
	if(int(keyArray[0]) == 0) {
		if(AES_set_encrypt_key(aes_key, 128, &enc_key)) {
            return false;
        }
		return true;
	} 
	else if(int(keyArray[0]) == 1) {
		if(AES_set_decrypt_key(aes_key, 128, &dec_key)) {
            return false;
        }
		return true;
	} 
	else {
        cout << "Invalid key type." << endl;
		return false;
	}
}

/**	
 * Encrypts a plaintext string
 * @param plaintext - the plaintext string
 * @return - the encrypted ciphertext string
 */
unsigned char* AES::encrypt(const unsigned char* plaintext) {

	//Allocating a block that holds 16 bytes
	uchar * ciphertext = new uchar[17]; 
	
	//Clearing the allocated array to store the ciphertext
	memset(ciphertext, 0, 17);

	//Encrypt
    AES_ecb_encrypt(plaintext, ciphertext, &enc_key, AES_ENCRYPT);

	//Return pointer to cipherText
	return ciphertext;
}

/**
 * Decrypts a string of ciphertext
 * @param cipherText - the ciphertext
 * @return - the plaintext
 */
unsigned char* AES::decrypt(const unsigned char* ciphertext) {
	
	//Allocating a block that holds 16 bytes
	uchar * plaintext = new uchar[17]; 

	//Clearing the allocted array to store the plaintext
	memset(plaintext, 0, 17);

	//Decrypt
	AES_ecb_encrypt(ciphertext, plaintext, &dec_key, AES_DECRYPT);
	
	//Return pointer to the plaintext
    return plaintext;
}
