#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <iostream>

// Function to create an RSA key pair and save to strings
void create_rsa_keys(std::string& public_key, std::string& private_key) {
    int key_length = 2048;  // Key length in bits
    RSA* rsa = RSA_new();
    BIGNUM* bignum = BN_new();
    BN_set_word(bignum, RSA_F4);  // Use the RSA_F4 public exponent

    // Generate key pair
    RSA_generate_key_ex(rsa, key_length, bignum, NULL);

    // To hold the keys
    BIO* pubkey_bio = BIO_new(BIO_s_mem());
    BIO* privkey_bio = BIO_new(BIO_s_mem());

    // Save keys to bio
    PEM_write_bio_RSAPublicKey(pubkey_bio, rsa);
    PEM_write_bio_RSAPrivateKey(privkey_bio, rsa, NULL, NULL, 0, NULL, NULL);

    // Key lengths
    size_t pubkey_len = BIO_pending(pubkey_bio);
    size_t privkey_len = BIO_pending(privkey_bio);

    // Allocate memory
    char* pubkey_char = new char[pubkey_len + 1];
    char* privkey_char = new char[privkey_len + 1];

    // Read from bio
    BIO_read(pubkey_bio, pubkey_char, pubkey_len);
    BIO_read(privkey_bio, privkey_char, privkey_len);

    // Null-terminate the strings
    pubkey_char[pubkey_len] = '\0';
    privkey_char[privkey_len] = '\0';

    // Convert to std::string
    public_key.assign(pubkey_char, pubkey_len);
    private_key.assign(privkey_char, privkey_len);

    // Cleanup
    RSA_free(rsa);
    BN_free(bignum);
    BIO_free_all(pubkey_bio);
    BIO_free_all(privkey_bio);
    delete[] pubkey_char;
    delete[] privkey_char;
}

// Function to encrypt a message
std::string rsa_encrypt(const std::string& public_key, const std::string& plain_text) {
    RSA* rsa = NULL;
    BIO* keybio = BIO_new_mem_buf((void*)public_key.c_str(), -1);
    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);

    int rsa_len = RSA_size(rsa);
    std::string cipher_text(rsa_len, '\0');

    RSA_public_encrypt(plain_text.length(), (const unsigned char*)plain_text.c_str(),
                       (unsigned char*)cipher_text.c_str(), rsa, RSA_PKCS1_PADDING);

    BIO_free_all(keybio);
    RSA_free(rsa);

    return cipher_text;
}

// Function to decrypt a message
std::string rsa_decrypt(const std::string& private_key, const std::string& cipher_text) {
    RSA* rsa = NULL;
    BIO* keybio = BIO_new_mem_buf((void*)private_key.c_str(), -1);
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

    int rsa_len = RSA_size(rsa);
    std::string decrypted_text(rsa_len, '\0');

    RSA_private_decrypt(cipher_text.size(), (const unsigned char*)cipher_text.c_str(),
                        (unsigned char*)decrypted_text.c_str(), rsa, RSA_PKCS1_PADDING);

    decrypted_text.resize(std::strlen(decrypted_text.c_str()));  // Resize to actual message length

    BIO_free_all(keybio);
    RSA_free(rsa);

    return decrypted_text;
}

int main() {
    std::string public_key, private_key;
    create_rsa_keys(public_key, private_key);

    std::string plain_text = "Hello, OpenSSL!";
    std::string cipher_text = rsa_encrypt(public_key, plain_text);
    std::string decrypted_text = rsa_decrypt(private_key, cipher_text);

    std::cout << "Original Text: " << plain_text << std::endl;
    std::cout << "Decrypted Text: " << decrypted_text << std::endl;

    return 0;
}
