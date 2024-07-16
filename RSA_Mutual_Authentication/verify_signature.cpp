#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <vector>

bool verify_signature(const std::string& data, const std::vector<unsigned char>& signature, const std::string& public_key_file) {
    FILE* key_file = fopen(public_key_file.c_str(), "r");
    RSA* rsa = PEM_read_RSA_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);

    bool result = RSA_verify(NID_sha256, reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), signature.data(), signature.size(), rsa) == 1;
    RSA_free(rsa);
    return result;
}

int main() {
    std::ifstream sender_pub_file("sender_public.pem");
    std::string sender_pub_key((std::istreambuf_iterator<char>(sender_pub_file)), std::istreambuf_iterator<char>());

    std::ifstream sig_file("sender_public.sig", std::ios::binary);
    std::vector<unsigned char> signature((std::istreambuf_iterator<char>(sig_file)), std::istreambuf_iterator<char>());

    bool valid = verify_signature(sender_pub_key, signature, "recipient_public.pem");

    if (valid) {
        std::cout << "Signature is valid.\n";
    } else {
        std::cout << "Signature is invalid.\n";
    }

    return 0;
}
