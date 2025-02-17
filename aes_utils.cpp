#include "aes_utils.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

// AES encryption function
bool aesEncryptFile(const string &inputFile, const string &outputFile, unsigned char *key, unsigned char *iv) {
    ifstream inFile(inputFile, ios::binary);
    ofstream outFile(outputFile, ios::binary);

    if (!inFile || !outFile) {
        cerr << "Error opening file!" << endl;
        return false;
    }

    // Save IV to the beginning of the file
    outFile.write((char *)iv, AES_BLOCK_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    vector<unsigned char> buffer(1024);
    vector<unsigned char> cipherBuffer(1024 + AES_BLOCK_SIZE);
    int len;

    while (inFile) {
        inFile.read((char *)buffer.data(), buffer.size());
        int bytesRead = inFile.gcount();

        if (bytesRead > 0) {
            EVP_EncryptUpdate(ctx, cipherBuffer.data(), &len, buffer.data(), bytesRead);
            outFile.write((char *)cipherBuffer.data(), len);
        }
    }

    EVP_EncryptFinal_ex(ctx, cipherBuffer.data(), &len);
    outFile.write((char *)cipherBuffer.data(), len);

    EVP_CIPHER_CTX_free(ctx);
    inFile.close();
    outFile.close();

    return true;
}

// AES decryption function
bool aesDecryptFile(const string &inputFile, const string &outputFile, unsigned char *key, unsigned char *iv) {
    ifstream inFile(inputFile, ios::binary);
    ofstream outFile(outputFile, ios::binary);

    if (!inFile || !outFile) {
        cerr << "Error opening file!" << endl;
        return false;
    }

    // Read IV from the beginning of the file
    inFile.read((char *)iv, AES_BLOCK_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    vector<unsigned char> buffer(1024);
    vector<unsigned char> plainBuffer(1024 + AES_BLOCK_SIZE);
    int len;

    while (inFile) {
        inFile.read((char *)buffer.data(), buffer.size());
        int bytesRead = inFile.gcount();

        if (bytesRead > 0) {
            EVP_DecryptUpdate(ctx, plainBuffer.data(), &len, buffer.data(), bytesRead);
            outFile.write((char *)plainBuffer.data(), len);
        }
    }

    int ret = EVP_DecryptFinal_ex(ctx, plainBuffer.data(), &len);
    if (ret <= 0) {
        cerr << "Decryption failed (Possible incorrect key/IV)!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        inFile.close();
        outFile.close();
        return false;
    }

    outFile.write((char *)plainBuffer.data(), len);

    EVP_CIPHER_CTX_free(ctx);
    inFile.close();
    outFile.close();

    return true;
}
