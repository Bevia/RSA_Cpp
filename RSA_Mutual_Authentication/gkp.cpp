#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>

void generate_key_pair(const std::string& private_key_file, const std::string& public_key_file) {
    RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    BIO* private_bio = BIO_new_file(private_key_file.c_str(), "w");
    PEM_write_bio_RSAPrivateKey(private_bio, rsa, NULL, NULL, 0, NULL, NULL);

    BIO* public_bio = BIO_new_file(public_key_file.c_str(), "w");
    PEM_write_bio_RSAPublicKey(public_bio, rsa);

    BIO_free_all(private_bio);
    BIO_free_all(public_bio);
    RSA_free(rsa);
}

int main() {
    generate_key_pair("sender_private.pem", "sender_public.pem");
    generate_key_pair("recipient_private.pem", "recipient_public.pem");
    return 0;
}
