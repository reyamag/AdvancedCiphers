#include <iostream>
#include <fstream>
#include <string>
#include <cassert>
#include "CipherInterface.h"
#include "DES.h"
#include "AES.h"

using std::cout;
using std::endl;
using std::string;
using std::ifstream;
using std::ofstream;
using std::ios;

#define AES_ENCRYPTION_FLAG 0x00;
#define AES_DECRYPTION_FLAG 0x01;

typedef unsigned char uchar;


// Prototypes
uchar * readFromFile(string, string, int);
void writeToFile(string, unsigned char *, int, string);

ifstream::pos_type true_filesize(string);
int functional_filesize(string, string);
int numberOfDESBlocks(string);
int findNumOfNulls(uchar *, int);

void printBlock(string, uchar *, int);
void printFile(string);


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
    if(!cipher) {
        fprintf(stderr, "ERROR [%s %s %d]: could not allocate memory\n",
                __FILE__, __FUNCTION__, __LINE__);
        exit(-1);
    }
    
    // Read input from the file
    uchar * uchar_input;

    // Designated output variables
    uchar * uchar_output;
    int sizeOfOutput = 0;

    if(cipherName == "DES") {

        // openssl processes uses the same key for DES encryption/decryption
        uchar * key = (uchar *)argv[2];
        if(!cipher->setKey(key)) {
            cerr << "Invalid key. Must be a 16-character string representing "
                 << "16 hexadecimal values (i.e., 64 bits).\n";
            return 1;
        }

        // DES is encrypted/decrypted in 8 byte blocks
        // First, determine the number of blocks
        int blocks = numberOfDESBlocks(inFileName);

        // The total size of our output
        sizeOfOutput = blocks * 8 + 1; // Plus 1 for NULL character
        
        uchar_input = new uchar[sizeOfOutput];
        memset(uchar_input, 0 , sizeOfOutput);
        uchar_input = readFromFile(inFileName, cipherName, sizeOfOutput);
        
        // Allocate memory
        uchar_output = new uchar[sizeOfOutput];
        memset(uchar_output, 0, sizeOfOutput);
        
        // Loop through each block, processing one at a time
        for(int i = 0; i < blocks; ++i) {
            // Get block
            uchar * currBlock = new uchar[8 + 1];
            memcpy(currBlock, uchar_input + 8*i, 8);
            currBlock[8] = 0; // Null terminating character

            uchar * blockProcessed = new uchar[8 + 1];

            // Perform encryption/decryption
            if(method == "ENC") {
                blockProcessed = cipher->encrypt(currBlock);
            } else if(method == "DEC") {
                blockProcessed = cipher->decrypt(currBlock);
            } else {
                cerr << "Invalid method! Please enter 'ENC' or 'DEC'.\n";
            }
            blockProcessed[8] = 0; // Null terminating character

            // Update master ciphertext with this encrypted block
            memcpy(uchar_output + 8*i, blockProcessed, 8);

            // Deallocate memory for the single block
            delete[] currBlock;
            delete[] blockProcessed;
        }

        uchar_output[blocks*8] = 0; // Null terminating character

    } else {

        /*-------------------AES PRE-PROCESSING OPERATIONS-------------------*/

        // Read in the key
        string key = argv[2];
        if(key.length() != 16) {
            cerr << "Invalid key lenght. Must be a 16-character string.\n";
            return 1;
        }

        // This implementation of AES encrypts/decrypts in 16-byte blocks
        // so we need to determine the number of blocks and allocate memory
        sizeOfOutput = functional_filesize(inFileName, "AES");

        // Ensure it's a multiple of 16.
        while((sizeOfOutput % 16) != 0) {
            ++sizeOfOutput;
        }
        
        // Allocate memory for the input given functional file size 
        uchar_input = new uchar[sizeOfOutput];
        memset(uchar_input, 0 , sizeOfOutput);
        //printBlock("In block pre:", uchar_input, sizeOfOutput);
        uchar_input = readFromFile(inFileName, cipherName, sizeOfOutput);
        //printBlock("In block after:", uchar_input, sizeOfOutput);

        // Determine the number of blocks
        int blocks = (sizeOfOutput / 16) + (sizeOfOutput % 16 == 0 ? 0 : 1);

        // Allocate/initialize memory for our output
        uchar_output = new uchar[sizeOfOutput];
        memset(uchar_output, 0, sizeOfOutput);

        // openssl processes setting up the AES encryption/decyprtion keys 
        // differently. To handle this, pass a 17 uchar array, with the 
        // first element indicating the type of key. 
        //
        // 0x00 = Encryption. 0x01 = Decryption.
        uchar uchar_key[17];
        memset(uchar_key, 0, 17);


        /*-------------------------AES BLOCK ENCRYPTION----------------------*/

        if(method == "ENC") {

            // Set key
            uchar_key[0] = AES_ENCRYPTION_FLAG;
            for(int i = 0; i < 16; ++i) {
                uchar_key[i+1] = int(key[i]);
            }
            if(!cipher->setKey(uchar_key)) {
                cerr << "Key unable to be setup :(\n";
                return 1;
            }

            int bytesLeft = sizeOfOutput;

            // Loop through each block, processing one at a time
            for(int i = 0; i < blocks; ++i) {

                uchar * currBlock;
                uchar * encryptedBlock = new uchar[17];
                memset(encryptedBlock, 0 , 17);

                // Input block is not guaranteed to be 16-bytes so we
                // have to allocate accordingly
                if(bytesLeft < 16) {
                    currBlock = new uchar[bytesLeft-1];
                    memcpy(currBlock, uchar_input + 16*i, bytesLeft-1);
                } else {
                    currBlock = new uchar[16];
                    memcpy(currBlock, uchar_input + 16*i, 16);
                }
                
                // Encrypt block
                encryptedBlock = cipher->encrypt(currBlock);

                // Append master ciphertext with this encrypted block
                memcpy(uchar_output + 16*i, encryptedBlock, 16);

                // Deallocate memory for the single block
                delete[] currBlock;
                delete[] encryptedBlock;

                bytesLeft -= 16;
            }

        } else if(method == "DEC") {

            sizeOfOutput = functional_filesize(inFileName, "AES");
            
            // Set key
            uchar_key[0] = AES_DECRYPTION_FLAG;
            for(int i = 0; i < 16; ++i) {
                uchar_key[i+1] = int(key[i]);
            }
            if(!cipher->setKey(uchar_key)) {
                cerr << "Key unable to be setup :(\n";
                return 1;
            }

            // Loop through each block, processing one at a time
            for(int i = 0; i < blocks; ++i) {
                
                // For decryption, we are guaranteed a discrete number of 
                // 16-byte blocks
                uchar * currBlock = new uchar[16];;
                uchar * blockProcessed = new uchar[17];;
                memcpy(currBlock, uchar_input + 16*i, 16);
                memset(blockProcessed, 0 , 17);

                blockProcessed = cipher->decrypt(currBlock);

                // Update master ciphertext with this encrypted block
                memcpy(uchar_output + 16*i, blockProcessed, 16);

                // Deallocate memory for the single block
                delete[] currBlock;
                delete[] blockProcessed;
            }

        } else {
            cerr << "Invalid method! Please enter 'ENC' or 'DEC'.\n";
        }
    }
    
    writeToFile(outFileName, uchar_output, sizeOfOutput, method);

    cout << (method == "ENC" ? "Encryption " : "Decryption ") << "successful!" << endl;
    
    cout << endl; // Pad terminal output
    return 0;
}


uchar * readFromFile(string filename, string cipher_type, int size) {
    
    //cout << "Read from file allocates " << size << " bytes\n";
    uchar * input = new uchar[size];
    memset(input, 0, size);
    ifstream inFile;
    inFile.open(filename.c_str());
    
    char c;
    int i = 0;
    while(i < size && inFile.get(c)) {
        input[i++] = uchar(c);
    }
    
    inFile.close();
    return input;
}

void writeToFile(string filename, unsigned char * uchar_input, int size, string method) {
    
    assert(method == "ENC" || method == "DEC");

    ofstream outFile;
    outFile.open(filename.c_str());

    // When decrypting, there will often be null characters padded at the end
    // the decrypted plaintext, which leads to undefined stream behavior.
    // Ignore these characters
    if(method == "DEC") {
        size -= findNumOfNulls(uchar_input, size);
    }

    // Write char by char since standard stream operators terminate upon reading
    // a null character, and encryption often leads to null characters dispersed
    // throughout the ciphertext.
    for(int i = 0; i < size; ++i) {
        outFile << uchar_input[i];
    }
    outFile.close();
}

// Returns the true filesize (in bytes) of the file
ifstream::pos_type true_filesize(string filename) {
    ifstream in(filename.c_str(), ifstream::ate | ifstream::binary);
    return in.tellg();
}

// Returns the functional filesize (in bytes)
// Ignores the final null character at the end of the file if
// the true_filesize is exactly one byte too large
int functional_filesize(string filename, string cipher) {

    assert(cipher == "AES" || cipher == "DES");

    // AES in 16-byte chunks DES in 8-byte chunks
    int group_size = 8;
    if(cipher == "AES") {
        group_size *= 2;
    }

    // Get true size
    int true_size = int(true_filesize(filename));

    if(true_size % group_size == 1) {
        ifstream inFile(filename.c_str());
        inFile.seekg(0, ios::end);
        inFile.seekg(-1, ios::cur);
        if(int(inFile.get()) == 0) {
            return true_size -= 1;
        }
    }
    return true_size;
}

// Finds the number of DES blocks (i.e., how many 8-byte chunks in the file)
int numberOfDESBlocks(string filename) {
    int size = functional_filesize(filename, "DES");
    
    int base = int(size / 8);
    int numberOfNulls = (8 - (size - 8*base)) % 8;
    return base + (numberOfNulls == 0 ? 0 : 1);
}

// Determines the number of padded null characters at the end of the file
int findNumOfNulls(uchar * buffer, int size) {

    int nulls = 0;
    for(int i = size-1; i >= 0; --i) {
        if(int(buffer[i]) == 0) {
            ++nulls;
        } else {
            // Exit upon first non-null character reached
            return nulls;
        }
    }
    return nulls;
}

// Debugging tools
void printBlock(string s, uchar * c, int size) {

    cout << "Printing block " << s << ":\n";
    for(int i = 0; i < size; ++i) {
        cout << i+1 << ": " << c[i] << "(" << int(c[i]) << ")\n";
    }
    cout << endl;
}

void printFile(string filename) {
    ifstream inFile;
    inFile.open(filename.c_str());

    inFile.seekg(0, ios::end);
    int size = inFile.tellg();
    inFile.seekg(0, ios::beg);

    char * buffer = new char[size + 1];
    uchar * ubuffer = new uchar[size + 1];
    memset(buffer, 0, size+1);
    memset(ubuffer, 0, size+1);
    inFile.read(buffer, size);

    int i;
    for(int i = 0 ; i < size; ++i) {
        ubuffer[i] = uchar(buffer[i]);
        cout << i+1 << ": " << buffer[i] << "(" << int(buffer[i]) << ")\n";
        cout << i+1 << ": " << ubuffer[i] << "(" << int(ubuffer[i]) << ")\n\n";
    }

    delete[] buffer;
    delete[] ubuffer;
}
