#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <vector>

bool verify_signature(const std::string& data, const std::vector<unsigned char>& signature, const std::string& public_key_file) {
    // Open the public key file
    FILE* key_file = fopen(public_key_file.c_str(), "r");
    if (!key_file) {
        std::cerr << "Error opening public key file." << std::endl;
        return false;
    }

    // Read the public key
    EVP_PKEY* evp_pkey = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!evp_pkey) {
        std::cerr << "Error reading public key." << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    RSA* rsa = EVP_PKEY_get1_RSA(evp_pkey);
    if (!rsa) {
        std::cerr << "Error extracting RSA key from EVP_PKEY." << std::endl;
        EVP_PKEY_free(evp_pkey);
        return false;
    }

    // Compute the SHA-256 hash of the data
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash)) {
        std::cerr << "Error computing SHA-256 hash." << std::endl;
        RSA_free(rsa);
        EVP_PKEY_free(evp_pkey);
        return false;
    }

    // Verify the signature
    bool result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), signature.size(), rsa) == 1;
    if (!result) {
        std::cerr << "Signature verification failed." << std::endl;
        ERR_print_errors_fp(stderr);
    }

    // Clean up
    RSA_free(rsa);
    EVP_PKEY_free(evp_pkey);
    return result;
}

int main() {
    // Read the sender's public key file
    std::ifstream sender_pub_file("sender_public.pem");
    if (!sender_pub_file) {
        std::cerr << "Error opening sender public key file." << std::endl;
        return 1;
    }
    std::string sender_pub_key((std::istreambuf_iterator<char>(sender_pub_file)), std::istreambuf_iterator<char>());

    // Read the signature file
    std::ifstream sig_file("sender_public.sig", std::ios::binary);
    if (!sig_file) {
        std::cerr << "Error opening signature file." << std::endl;
        return 1;
    }
    std::vector<unsigned char> signature((std::istreambuf_iterator<char>(sig_file)), std::istreambuf_iterator<char>());

    // Verify the signature
    bool valid = verify_signature(sender_pub_key, signature, "recipient_public.pem");

    if (valid) {
        std::cout << "Signature is valid.\n";
    } else {
        std::cout << "Signature is invalid.\n";
    }

    return 0;
}
