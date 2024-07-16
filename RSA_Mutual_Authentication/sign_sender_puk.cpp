#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <vector>

std::vector<unsigned char> sign_data(const std::string& data, const std::string& private_key_file) {
    FILE* key_file = fopen(private_key_file.c_str(), "r");
    RSA* rsa = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    std::vector<unsigned char> signature(RSA_size(rsa));
    unsigned int signature_len;

    if (RSA_sign(NID_sha256, reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), signature.data(), &signature_len, rsa) == 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    RSA_free(rsa);
    signature.resize(signature_len);
    return signature;
}

int main() {
    std::ifstream sender_pub_file("sender_public.pem");
    std::string sender_pub_key((std::istreambuf_iterator<char>(sender_pub_file)), std::istreambuf_iterator<char>());

    std::vector<unsigned char> signature = sign_data(sender_pub_key, "recipient_private.pem");

    std::ofstream signature_file("sender_public.sig", std::ios::binary);
    signature_file.write(reinterpret_cast<const char*>(signature.data()), signature.size());
    signature_file.close();

    return 0;
}
