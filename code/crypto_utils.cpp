#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdexcept>

using namespace std;

vector<unsigned char> pkcs7_pad(vector<unsigned char>& data)
{
    int block_size = 16;
    int padding_length = block_size - (data.size() % block_size);
    vector<unsigned char> padded_data = data;
    for (int i = 0; i < padding_length; i++)
        padded_data.push_back(padding_length);
    return padded_data;
}

bool pkcs7_unpad(vector<unsigned char>& data)
{
    int padding_length = data.back();
    if (padding_length > 16 || padding_length == 0)
        return false;
    for (int i = 0; i < padding_length; i++)
        if (data[data.size() - 1 - i] != padding_length)
            return false;
    data.resize(data.size() - padding_length);
    return true;
}

vector<unsigned char> random_iv()
{
    vector<unsigned char> iv(16);
    for (int i = 0; i < 16; i++)
        iv[i] = rand() % 256;
    return iv;
}

// AES CBC encryption
// Must handle runtime exceptions and errors when called
vector<unsigned char> aes_cbc_encrypt(
    vector<unsigned char>& padded_plaintext,
    vector<unsigned char>& key,
    vector<unsigned char>& iv
)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        throw runtime_error("CTX allocation failed");
    if(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data()) != 1)
        throw runtime_error("EncryptInit failed");

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    vector<unsigned char> ciphertext(padded_plaintext.size() + 16);
    int len1 = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len1, padded_plaintext.data(), padded_plaintext.size()) != 1)
        throw runtime_error("EncryptUpdate failed");

    int len2 = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len1, &len2) != 1)
        throw runtime_error("EncryptFinal failed");

    ciphertext.resize(len1 + len2);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// AES CBC decryption
// Must handle runtime exceptions and errors when called
// Returns the decrypted plaintext (still padded)
vector<unsigned char> aes_cbc_decrypt(
    vector<unsigned char>& ciphertext,
    vector<unsigned char>& key,
    vector<unsigned char>& iv
)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        throw runtime_error("CTX allocation failed");
    if(EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data()) != 1)
        throw runtime_error("DecryptInit failed");

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    vector<unsigned char> plaintext(ciphertext.size());
    int len1 = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len1, ciphertext.data(), ciphertext.size()) != 1)
        throw runtime_error("DecryptUpdate failed");

    int len2 = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len1, &len2) != 1)
        throw runtime_error("DecryptFinal failed");
    
    plaintext.resize(len1 + len2);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// | Opcode (1) | Client ID (1) | Round (4) | Direction (1) | IV (16)| Ciphertext (variable) | HMAC (32) |
// The HMAC covers all preceding fields, so data should be everything except the HMAC
// Must handle runtime exceptions and errors when called
vector<unsigned char> compute_hmac(
    vector<unsigned char>& data,
    vector<unsigned char>& mac_key
)
{
    vector<unsigned char> mac(32);
    unsigned int mac_len = 0;

    if (HMAC(EVP_sha256(), mac_key.data(), mac_key.size(), data.data(), data.size(), mac.data(), &mac_len) == nullptr)
        throw runtime_error("HMAC computation failed");

    if (mac_len != 32)
        throw runtime_error("Unexpected HMAC length");

    return mac;
}

bool verify_hmac(
    vector<unsigned char>& data,
    vector<unsigned char>& mac_key,
    vector<unsigned char>& received_mac
)
{
    if (received_mac.size() != 32)
        return false;
    
    vector<unsigned char> expected_mac = compute_hmac(data, mac_key);
    unsigned char diff = 0;
    for (int i=0;i<32;i++)
        diff |= (expected_mac[i] ^ received_mac[i]);

    return diff == 0;
}