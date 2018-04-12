#include <iostream>
#include <fstream>
#include <string>
#include "CipherInterface.h"
#include "DES.h"
#include "AES.h"

using namespace std;

typedef unsigned char uchar;

// From Stacked Overflow: https://stackoverflow.com/questions/5840148/how-can-i-get-a-files-size-in-c
std::ifstream::pos_type filesize(string filename) {
    std::ifstream in(filename.c_str(), std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
}

int numberOfBlocks(string filename) {
    int size = int(filesize(filename));
    
    const int BYTE_SIZE = 8;
    
    int base = int((size) / BYTE_SIZE);
    int numberOfNulls = (BYTE_SIZE - (size - BYTE_SIZE*base)) % BYTE_SIZE;
    return base + (numberOfNulls == 0 ? 0 : 1);
}

uchar * readFromFile(string filename, bool DES_padding = false) {
    
    int arrayLength = int(filesize(filename));
    int numberOfNulls = 0;
    
    if(DES_padding) {
        const int BYTE_SIZE = 8;
        
        int base = int((arrayLength) / BYTE_SIZE);
        numberOfNulls = (BYTE_SIZE - (arrayLength - BYTE_SIZE*base)) % BYTE_SIZE;
        arrayLength = (BYTE_SIZE * (base + (numberOfNulls == 0 ? 0 : 1)));
    }
    
    uchar * input = new uchar[arrayLength];
    ifstream inFile;
    inFile.open(filename.c_str());
    
    char c;
    int i = 0;
    while(inFile.get(c)) {
        input[i++] = uchar(c);
    }
    for(int i = 0; i < numberOfNulls; ++i) {
        input[arrayLength-1-i] = 0;
    }
    
    inFile.close();
    return input;
}

void writeToFile(string filename, unsigned char * uchar_input) {
    
    ofstream outFile;
    outFile.open(filename.c_str());
    outFile << uchar_input;
    outFile.close();
}

int main(int argc, char** argv)
{
    /**
     * TODO: Replace the code below    with your code which can SWITCH
     * between DES and AES and encrypt files. DO NOT FORGET TO PAD
     * THE LAST BLOCK IF NECESSARY.
     *
     * NOTE: due to the incomplete skeleton, the code may crash or
     * misbehave.
     */
    
    if(argc != 6) {
        cerr << "Incorrect number of arguments!\n";
        return 1;
    }
    
    string cipherName = argv[1],
    method = argv[3],
    inFileName = argv[4],
    outFileName = argv[5];
    
    uchar * key = (uchar *)argv[2];
    
    
    /* Create an instance of the cipher */
    CipherInterface* cipher = NULL;
    
    if(cipherName == "DES") {
        cipher = new DES();
    } else if(cipherName == "AES") {
        cipher = new AES();
    } else {
        cerr << "Invalid cipher type. Please enter 'DES' or 'AES'\n";
        return 1;
    }
    
    /* Error checks */
    if(!cipher)
    {
        fprintf(stderr, "ERROR [%s %s %d]: could not allocate memory\n",
                __FILE__, __FUNCTION__, __LINE__);
        exit(-1);
    }
    
    /* Set the encryption key
     * A valid key comprises 16 hexidecimal
     * characters. Below is one example.
     * Your program should take input from
     * command line.
     */
    cipher->setKey(key);
    
    /* Read input from the file */
    uchar * uchar_input = readFromFile(inFileName, cipherName == "DES");
    uchar * uchar_output;
    if(method == "ENC") {
        if(cipherName == "DES") {
            // DES is encrypted in 8 byte blocks
            // First, determine the number of blocks
            int blocks = numberOfBlocks(inFileName);
            // The total size of our ciphertext
            uchar_output = new uchar[blocks*8];
            
            // Loop through each block, encrypted one at a time
            for(int i = 0; i < blocks; ++i) {
                // Get block
                uchar singleBlock[8];
                memcpy(singleBlock, uchar_input + 8*i, 8);
                
                // Encrypt block
                uchar * blockEncrypted = cipher->encrypt(singleBlock);
                
                // Update master ciphertext with this encrypted block
                for(int j = 0; j < 8; ++j) {
                    uchar_output[i*8 + j] = blockEncrypted[j];
                }
            }
        } else {
            // AES is easy
            uchar_output = cipher->encrypt(uchar_input);
        }
    } else if(method == "DEC") {
        if(cipherName == "DES") {
            // DES is decrypted in 8 byte blocks
            // First, determine the number of blocks
            int blocks = numberOfBlocks(inFileName);
            // The total size of our plaintext
            uchar_output = new uchar[blocks*8];
            
            // Loop through each block, decrypted one at a time
            for(int i = 0; i < blocks; ++i) {
                // Get block
                uchar singleBlock[8];
                memcpy(singleBlock, uchar_input + 8*i, 8);
                
                // Encrypt block
                uchar * blockDecrypted = cipher->decrypt(singleBlock);
                
                // Update master ciphertext with this encrypted block
                for(int j = 0; j < 8; ++j) {
                    uchar_output[i*8 + j] = blockDecrypted[j];
                }
            }
        } else {
            // AES is easy
            uchar_output = cipher->encrypt(uchar_input);
        }
    } else {
        cerr << "Invalid method! Please enter 'ENC' or 'DEC'.\n";
        return 1;
    }
    
    writeToFile(outFileName, uchar_output);
    
    return 0;
}
