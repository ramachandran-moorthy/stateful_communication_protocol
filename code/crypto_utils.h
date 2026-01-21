#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <cstdint>

using namespace std;

vector<unsigned char> pkcs7_pad(vector<unsigned char>& data);
bool pkcs7_unpad(vector<unsigned char>& data);

vector<unsigned char> random_iv();

vector<unsigned char> aes_cbc_encrypt(
    vector<unsigned char>& padded_plaintext,
    vector<unsigned char>& key,
    vector<unsigned char>& iv
);

vector<unsigned char> aes_cbc_decrypt(
    vector<unsigned char>& ciphertext,
    vector<unsigned char>& key,
    vector<unsigned char>& iv
);

vector<unsigned char> compute_hmac(
    vector<unsigned char>& data,
    vector<unsigned char>& mac_key
);

bool verify_hmac(
    vector<unsigned char>& data,
    vector<unsigned char>& mac_key,
    vector<unsigned char>& received_mac
);

#endif