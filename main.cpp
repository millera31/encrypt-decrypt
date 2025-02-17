#include <iostream>
#include <openssl/rand.h>
#include "aes_utils.h"

using namespace std;

int main() {
    unsigned char key[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    unsigned char iv[AES_BLOCK_SIZE];

    int choice;
    string inputFile, outputFile;

    cout << "AES File Encryption/Decryption\n";
    cout << "1. Encrypt a file\n";
    cout << "2. Decrypt a file\n";
    cout << "Choose an option: ";
    cin >> choice;

    if (choice == 1) {
        cout << "Enter file to encrypt: ";
        cin >> inputFile;
        cout << "Enter output encrypted file: ";
        cin >> outputFile;

        // Generate a random IV
        if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
            cerr << "Error generating random IV!" << endl;
            return 1;
        }

        if (aesEncryptFile(inputFile, outputFile, key, iv)) {
            cout << "Encryption successful. Output file: " << outputFile << endl;
        } else {
            cout << "Encryption failed." << endl;
        }

    } else if (choice == 2) {
        cout << "Enter file to decrypt: ";
        cin >> inputFile;
        cout << "Enter output decrypted file: ";
        cin >> outputFile;

        // IV is read from the encrypted file in aesDecryptFile
        if (aesDecryptFile(inputFile, outputFile, key, iv)) {
            cout << "Decryption successful. Output file: " << outputFile << endl;
        } else {
            cout << "Decryption failed." << endl;
        }

    } else {
        cout << "Invalid option!" << endl;
    }

    return 0;
}
