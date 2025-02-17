#ifndef AES_UTILS_H
#define AES_UTILS_H

#include <string>
#include <openssl/evp.h>

#define AES_BLOCK_SIZE 16

bool aesEncryptFile(const std::string &inputFile, const std::string &outputFile, unsigned char *key, unsigned char *iv);
bool aesDecryptFile(const std::string &inputFile, const std::string &outputFile, unsigned char *key, unsigned char *iv);

#endif // AES_UTILS_H
