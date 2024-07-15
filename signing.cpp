#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <cstring>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to generate RSA key pair
RSA* generateKeyPair() {
    int bits = 2048;
    unsigned long e = RSA_F4;

    RSA* rsa = RSA_new();
    BIGNUM* bne = BN_new();
    if (!BN_set_word(bne, e)) handleErrors();

    if (!RSA_generate_key_ex(rsa, bits, bne, NULL)) handleErrors();

    BN_free(bne);
    return rsa;
}

// Function to sign a message
std::string signMessage(RSA* privateKey, const std::string& message) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);

    unsigned char* signature = new unsigned char[RSA_size(privateKey)];
    unsigned int signatureLen;
    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &signatureLen, privateKey) != 1) {
        handleErrors();
    }

    std::string signatureStr(reinterpret_cast<char*>(signature), signatureLen);
    delete[] signature;
    return signatureStr;
}

// Function to verify a signature
bool verifySignature(RSA* publicKey, const std::string& message, const std::string& signature) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);

    if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
    reinterpret_cast<const unsigned char*>(signature.c_str()), signature.length(), publicKey) != 1) {
        return false;
    }
    return true;
}

int main() {
    // Generate RSA key pair
    RSA* keyPair = generateKeyPair();

    // Extract and print public key
    BIO* pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub, keyPair);
    size_t pub_len = BIO_pending(pub);
    char* pub_key = new char[pub_len + 1];
    BIO_read(pub, pub_key, pub_len);
    pub_key[pub_len] = '\0';
    std::cout << "Public Key:\n" << pub_key << std::endl;
    BIO_free_all(pub);
    delete[] pub_key;

    // Message to be signed
    std::string message = "Hello, Bob!";

    // Sign the message
    std::string signature = signMessage(keyPair, message);
    std::cout << "Signature (hex): ";
    for (unsigned char c : signature) {
        std::cout << std::hex << (int)c;
    }
    std::cout << std::endl;

    // Verify the signature
    bool isValid = verifySignature(keyPair, message, signature);
    if (isValid) {
        std::cout << "The signature is valid." << std::endl;
    } else {
        std::cout << "The signature is invalid." << std::endl;
    }

    // Clean up
    RSA_free(keyPair);

    return 0;
}
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <cstring>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to generate RSA key pair
RSA* generateKeyPair() {
    int bits = 2048;
    unsigned long e = RSA_F4;

    RSA* rsa = RSA_new();
    BIGNUM* bne = BN_new();
    if (!BN_set_word(bne, e)) handleErrors();

    if (!RSA_generate_key_ex(rsa, bits, bne, NULL)) handleErrors();

    BN_free(bne);
    return rsa;
}

// Function to sign a message
std::string signMessage(RSA* privateKey, const std::string& message) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);

    unsigned char* signature = new unsigned char[RSA_size(privateKey)];
    unsigned int signatureLen;
    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &signatureLen, privateKey) != 1) {
        handleErrors();
    }

    std::string signatureStr(reinterpret_cast<char*>(signature), signatureLen);
    delete[] signature;
    return signatureStr;
}

// Function to verify a signature
bool verifySignature(RSA* publicKey, const std::string& message, const std::string& signature) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);

    if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
                   reinterpret_cast<const unsigned char*>(signature.c_str()), signature.length(), publicKey) != 1) {
        return false;
    }
    return true;
}

int main() {
    // Generate RSA key pair
    RSA* keyPair = generateKeyPair();

    // Extract and print public key
    BIO* pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub, keyPair);
    size_t pub_len = BIO_pending(pub);
    char* pub_key = new char[pub_len + 1];
    BIO_read(pub, pub_key, pub_len);
    pub_key[pub_len] = '\0';
    std::cout << "Public Key:\n" << pub_key << std::endl;
    BIO_free_all(pub);
    delete[] pub_key;

    // Message to be signed
    std::string message = "Hello, Bob!";

    // Sign the message
    std::string signature = signMessage(keyPair, message);
    std::cout << "Signature (hex): ";
    for (unsigned char c : signature) {
        std::cout << std::hex << (int)c;
    }
    std::cout << std::endl;

    // Verify the signature
    bool isValid = verifySignature(keyPair, message, signature);
    if (isValid) {
        std::cout << "The signature is valid." << std::endl;
    } else {
        std::cout << "The signature is invalid." << std::endl;
    }

    // Clean up
    RSA_free(keyPair);

    return 0;
}
