#include <iostream>
#include <fstream>
#include <string>
#include "CipherInterface.h"
#include "DES.h"
#include "AES.h"

using std::cout;
using std::endl;
using std::string;

typedef unsigned char uchar;

// From Stacked Overflow: https://stackoverflow.com/questions/5840148/how-can-i-get-a-files-size-in-c
std::ifstream::pos_type filesize(string filename) {
    std::ifstream in(filename.c_str(), std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
}

int DES_filesize(string filename) {
    int true_size = int(filesize(filename));

    if(true_size % 8 == 1) {
        ifstream inFile(filename.c_str());
        inFile.seekg(0, std::ios::end);
        inFile.seekg(-1, std::ios::cur);
        if(int(inFile.get()) == 0) {
            return true_size -= 1;
        }
    }
    return true_size;
}

int AES_filesize(string filename) {
    int true_size = int(filesize(filename));

    if(true_size % 16 == 1) {
        ifstream inFile(filename.c_str());
        inFile.seekg(0, std::ios::end);
        inFile.seekg(-1, std::ios::cur);
        if(int(inFile.get()) == 0) {
            return true_size -= 1;
        }
    }
    return true_size;
}

int numberOfBlocks(string filename) {
    int size = DES_filesize(filename);
    
    const int BYTE_SIZE = 8;
    
    int base = int((size) / BYTE_SIZE);
    int numberOfNulls = (BYTE_SIZE - (size - BYTE_SIZE*base)) % BYTE_SIZE;
    return base + (numberOfNulls == 0 ? 0 : 1);
}

int numofAESblocks(string filename) {
    int size = AES_filesize(filename);
    
    const int BYTE_SIZE = 16;
    
    int base = int((size) / BYTE_SIZE);
    int numberOfNulls = (BYTE_SIZE - (size - BYTE_SIZE*base)) % BYTE_SIZE;
    return base + (numberOfNulls == 0 ? 0 : 1);
}

uchar * readFromFile(string filename, bool DES_padding = false) {
    
    int arrayLength = int(filesize(filename));
    int numberOfNulls = 0;
    
    if(DES_padding) {
        const int BYTE_SIZE = 8;

        arrayLength = DES_filesize(filename); // Override if DES
        
        int base = int((arrayLength) / BYTE_SIZE);

        numberOfNulls = (BYTE_SIZE - (arrayLength - BYTE_SIZE*base)) % BYTE_SIZE;
        arrayLength = (BYTE_SIZE * (base + (numberOfNulls == 0 ? 0 : 1)));
    }
    
    uchar * input = new uchar[arrayLength];
    ifstream inFile;
    inFile.open(filename.c_str());
    
    char c;
    int i = 0;
    while(i < arrayLength && inFile.get(c)) {
        input[i++] = uchar(c);
    }
    for(int i = 0; i < numberOfNulls; ++i) {
        input[arrayLength-1-i] = 0;
    }
    
    inFile.close();
    return input;
}

uchar * readFileForAES(string filename, bool AES_padding = false) {
    
    int arrayLengthAES = int(filesize(filename));
    int numberOfNulls = 0;
    
    if(AES_padding) {
        const int BYTE_SIZE = 16;

        arrayLengthAES = AES_filesize(filename); // Override if DES
        
        int base = int((arrayLengthAES) / BYTE_SIZE);

        numberOfNulls = (BYTE_SIZE - (arrayLengthAES - BYTE_SIZE*base)) % BYTE_SIZE;
        arrayLengthAES = (BYTE_SIZE * (base + (numberOfNulls == 0 ? 0 : 1)));
    }
    
    uchar * input = new uchar[arrayLengthAES];
    ifstream inFile;
    inFile.open(filename.c_str());
    
    char c;
    int i = 0;
    while(i < arrayLengthAES && inFile.get(c)) {
        input[i++] = uchar(c);
    }
    for(int i = 0; i < numberOfNulls; ++i) {
        input[arrayLengthAES-1-i] = 0;
    }
    
    inFile.close();
    return input;
}

void writeToFile(string filename, unsigned char * uchar_input, int sizeOfInput) {
    
    ofstream outFile;
    outFile.open(filename.c_str());
    for(int i = 0; i < sizeOfInput; ++i) {
        outFile << uchar_input[i];
    }
    outFile.close();
}

int main(int argc, char** argv) {
    
    cout << endl; // Pad terminal output.
    
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
    int sizeOfOutput = 0;
    
    uchar * uchar_inputAES = readFromFile(inFileName, cipherName == "AES");
    uchar * uchar_outputAES;
    int sizeOfOutputAES = 0;

    if(cipherName == "DES") {
        // DES is encrypted/decrypted in 8 byte blocks
        // First, determine the number of blocks
        int blocks = numberOfBlocks(inFileName);

        // The total size of our input
        sizeOfOutput = blocks*8 + 1;
        uchar_output = new uchar[sizeOfOutput];
        memset(uchar_output, 0, sizeOfOutput);
        
        // Loop through each block, processing one at a time
        for(int i = 0; i < blocks; ++i) 
        {
            // Get block
            uchar * singleBlock = new uchar[9];
            memcpy(singleBlock, uchar_input + 8*i, 8);
            singleBlock[8] = 0; // Null terminating character

            uchar * blockProcessed = new uchar[9];
            // Perform encryption/decryption
            if(method == "ENC") {
                blockProcessed = cipher->encrypt(singleBlock);
            } else if(method == "DEC") {
                blockProcessed = cipher->decrypt(singleBlock);
            } else {
                cerr << "Invalid method! Please enter 'ENC' or 'DEC'.\n";
            }
            blockProcessed[8] = 0; // Null terminating character

            // Update master ciphertext with this encrypted block
            memcpy(uchar_output + 8*i, blockProcessed, 8);

            // Deallocate memory for the single block
            delete[] singleBlock;
            delete[] blockProcessed;
        }
        uchar_output[blocks*8] = 0; // Null terminating character
        
    } else if (cipherName == "AES"){
        // AES encrypts/decrypts in 16 byte blocks
        // First, determine the number of blocks
        int AESblocks = numofAESblocks(inFileName);

        // The total size of our input
        sizeOfOutputAES = blocks*16 + 1;
        uchar_outputAES = new uchar[sizeOfOutputAES];
        memset(uchar_outputAES, 0, sizeOfOutputAES);
        
        // Loop through each block, processing one at a time
        for(int i = 0; i < blocks; ++i) 
        {
            // Get block
            uchar * singleBlockAES = new uchar[16];
            memcpy(singleBlockAES, uchar_inputAES + 16*i, 16);
            singleBlockAES[16] = 0; // Null terminating character

            uchar * AESblock = new uchar[17];
            // Perform encryption/decryption
            if(method == "ENC") {
                AESblock = cipher->encrypt(singleBlockAES);
            } else if(method == "DEC") {
                AESblock = cipher->decrypt(singleBlockAES);
            } else {
                cerr << "Invalid method! Please enter 'ENC' or 'DEC'.\n";
            }
            AESblock[16] = 0; // Null terminating character

            // Update master ciphertext with this encrypted block
            memcpy(uchar_outputAES + 16*i, AESblock, 16);

            // Deallocate memory for the single block
            delete[] singleBlockAES;
            delete[] AESblock;
        }
        uchar_outputAES[AESblocks*16] = 0; // Null terminating character 
    }
    else {
        if(method == "ENC") {
            uchar_output = cipher->encrypt(uchar_input);
        } else if(method == "DEC") {
            uchar_output = cipher->decrypt(uchar_input);
        } else {
            cerr << "Invalid method! Please enter 'ENC' or 'DEC'.\n";
        }
    }
    
    writeToFile(outFileName, uchar_output, sizeOfOutput);

    cout << (method == "ENC" ? "Encryption " : "Decryption ") << "successful!" << endl;
    
    cout << endl; // Pad terminal output
    return 0;
}
