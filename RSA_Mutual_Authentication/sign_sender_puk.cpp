#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <vector>

std::vector<unsigned char> sign_data(const std::string& data, const std::string& private_key_file) {
    // Open the private key file
    FILE* key_file = fopen(private_key_file.c_str(), "r");
    if (!key_file) {
        std::cerr << "Error opening private key file." << std::endl;
        exit(1);
    }

    // Read the private key
    RSA* rsa = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!rsa) {
        std::cerr << "Error reading private key." << std::endl;
        exit(1);
    }

    // Print RSA key size
    std::cout << "RSA key size: " << RSA_size(rsa) << " bytes" << std::endl;
    std::cout << std::flush; // Ensure the output is flushed to the terminal

    // Compute the SHA-256 hash of the data
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash)) {
        std::cerr << "Error computing SHA-256 hash." << std::endl;
        RSA_free(rsa);
        exit(1);
    }

    // Print SHA-256 digest size
    std::cout << "SHA-256 digest size: " << SHA256_DIGEST_LENGTH << " bytes" << std::endl;
    std::cout << std::flush; // Ensure the output is flushed to the terminal

    // Sign the hash
    std::vector<unsigned char> signature(RSA_size(rsa));
    unsigned int signature_len;
    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), &signature_len, rsa) == 0) {
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        exit(1);
    }

    // Clean up
    RSA_free(rsa);
    signature.resize(signature_len);
    return signature;
}

int main() {
    // Read the sender's public key file
    std::ifstream sender_pub_file("sender_public.pem");
    if (!sender_pub_file) {
        std::cerr << "Error opening sender public key file." << std::endl;
        return 1;
    }
    std::string sender_pub_key((std::istreambuf_iterator<char>(sender_pub_file)), std::istreambuf_iterator<char>());

    // Sign the sender's public key with the recipient's private key
    std::vector<unsigned char> signature = sign_data(sender_pub_key, "recipient_private.pem");

    // Write the signature to a file
    std::ofstream signature_file("sender_public.sig", std::ios::binary);
    if (!signature_file) {
        std::cerr << "Error opening signature file for writing." << std::endl;
        return 1;
    }
    signature_file.write(reinterpret_cast<const char*>(signature.data()), signature.size());
    signature_file.close();

    return 0;
}
