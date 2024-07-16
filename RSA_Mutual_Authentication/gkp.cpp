#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>

void generate_and_print_key_pair(const std::string& private_key_file, const std::string& public_key_file) {
    // Generate the RSA key pair
    RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa) {
        std::cerr << "Error generating RSA key pair." << std::endl;
        return;
    }

    // Write private key to file
    BIO* private_bio = BIO_new_file(private_key_file.c_str(), "w");
    if (!PEM_write_bio_RSAPrivateKey(private_bio, rsa, NULL, NULL, 0, NULL, NULL)) {
        std::cerr << "Error writing private key to file." << std::endl;
        BIO_free_all(private_bio);
        RSA_free(rsa);
        return;
    }

    // Write public key to file
    BIO* public_bio = BIO_new_file(public_key_file.c_str(), "w");
    if (!PEM_write_bio_RSAPublicKey(public_bio, rsa)) {
        std::cerr << "Error writing public key to file." << std::endl;
        BIO_free_all(private_bio);
        BIO_free_all(public_bio);
        RSA_free(rsa);
        return;
    }

    // Print the private key to the console
    BIO* private_bio_out = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSAPrivateKey(private_bio_out, rsa, NULL, NULL, 0, NULL, NULL)) {
        std::cerr << "Error writing private key to memory BIO." << std::endl;
    } else {
        BUF_MEM* private_buf;
        BIO_get_mem_ptr(private_bio_out, &private_buf);
        std::cout << "Private Key:\n" << std::string(private_buf->data, private_buf->length) << std::endl;
    }
    BIO_free_all(private_bio_out);

    // Print the public key to the console
    BIO* public_bio_out = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSAPublicKey(public_bio_out, rsa)) {
        std::cerr << "Error writing public key to memory BIO." << std::endl;
    } else {
        BUF_MEM* public_buf;
        BIO_get_mem_ptr(public_bio_out, &public_buf);
        std::cout << "Public Key:\n" << std::string(public_buf->data, public_buf->length) << std::endl;
    }
    BIO_free_all(public_bio_out);

    // Clean up
    BIO_free_all(private_bio);
    BIO_free_all(public_bio);
    RSA_free(rsa);
}

int main() {
    std::cout << "Sender Keys:" << std::endl;
    generate_and_print_key_pair("sender_private.pem", "sender_public.pem");

    std::cout << "\nRecipient Keys:" << std::endl;
    generate_and_print_key_pair("recipient_private.pem", "recipient_public.pem");

    return 0;
}
