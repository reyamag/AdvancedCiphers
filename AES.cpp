#include "AES.h"
#include <string>
#include <iostream>
#include <stdio.h>
#include <openssl/aes.h>

/**
 * Sets the key to use
 * @param key - the first byte of this represents whether
 * to encrypt or to decrypt. 00 means encrypt and any other
 * value to decrypt.  Then come the bytes of the 128-bit key
 * (should be 16 of them).
 * @return - True if the key is valid and False otherwise
 */
bool AES::setKey(const unsigned char* keyArray[])
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
	
	string keyArray[17];

	//Checking for the first byte to see if the key is going to be used for 
	//encrpytion or decrpyption
	if (keyArray[0] == 0)
	{
		AES_KEY enc_key;
		AES_set_encrpyt_key(aes_key, 128, &enc_key);
		return true;
	} 
	else if (keyArray[0] > 0)
	{
		AES_KEY dec_key;
		AES_set_decrpyt_key(aes_key, 128, &dec_key);
		return true;
	} 
	else
	{
		return false;
	}
}

/**	
 * Encrypts a plaintext string
 * @param plaintext - the plaintext string
 * @return - the encrypted ciphertext string
 */
unsigned char* AES::encrypt(const unsigned char* plainText)
{
	//TODO: 1. Dynamically allocate a block to store the ciphertext.
	//	2. Use AES_ecb_encrypt(...) to encrypt the text (please see the URL in setKey(...)
	//	and the aes.cpp example provided.
	// 	3. Return the pointer to the ciphertext

	string *cipherText = NULL;
	cipherText = new string[16]; //Allocating a block that holds 16 bytes

	//Declare needed for the encrypt function
	unsigned char enc_out[17];
	memset(enc_out, 0, 17);
	AES_KEY enc_key;

	//Encrypt
	AES_ecb_encrypt(plainText, enc_out, &enc_key, AES_ENCRYPT);
	
	for (int i = 0; i < 16; i++)
	{
		cipherText[i] = plainText;
	}
	
	//Return pointer to cipherText
	return cipherText;	
}

/**
 * Decrypts a string of ciphertext
 * @param cipherText - the ciphertext
 * @return - the plaintext
 */
unsigned char* AES::decrypt(const unsigned char* cipherText)
{
	//TODO: 1. Dynamically allocate a block to store the plaintext.
	//	2. Use AES_ecb_encrypt(...) to decrypt the text (please see the URL in setKey(...)
	//	and the aes.cpp example provided.
	// 	3. Return the pointer to the plaintext

	int *plainTextAfterDec = NULL;
	plainTextAfterDec = new int[16]; //Allocating a block that holds 16 bytes

	//Declare needed for the decrypt function
	unsigned char dec_out[17];
	memset(dec_out, 0, 17);
	AES_KEY dec_key;

	//Decrypt
	AES_ecb_encrypt(cipherText, dec_out, &dec_key, AES_DECRYPT);

	for (int i = 0; i < 16; i++)
	{
		plainTextAfterDec[i] = cipherText;
	}
	
	//Return pointer to the plaintext
	return plainTextAfterDec;
}



