#ifndef CRYPTO_H
#define CRYPTO_H

#include <blake3.h>
#include <openssl/evp.h>
#include <stdbool.h>

typedef struct encrypt_state {
    EVP_CIPHER_CTX *ctx;
    blake3_hasher hasher;

    uint8_t derived_key[32];
    uint8_t encryption_key[32];
    uint8_t hmac_key[32];

    uint8_t salt[32];
} encrypt_state_t;

typedef struct decrypt_state {
    EVP_CIPHER_CTX *ctx;
    blake3_hasher hasher;

    uint8_t derived_key[32];
    uint8_t encryption_key[32];
    uint8_t hmac_key[32];

    uint8_t hmac[32];

    uint8_t salt[32];
} decrypt_state_t;

enum cipher_algorithm { ALGORITHM_AES, ALGORITHM_CHACHA20 };

void encrypt_free(encrypt_state_t *state);
bool encrypt_init(encrypt_state_t *state, const char *password,
                  enum cipher_algorithm algorithm);
bool encrypt_update(encrypt_state_t *state, void *input, int input_length,
                    void *output);
void encrypt_finalize(encrypt_state_t *state, uint8_t *tag_out,
                      uint8_t *salt_out);

void decrypt_free(decrypt_state_t *state);
bool decrypt_init(decrypt_state_t *state, const char *password, uint8_t *salt,
                  uint8_t *hmac, enum cipher_algorithm algorithm);
bool decrypt_update(decrypt_state_t *state, void *input, int input_length,
                    void *output);
bool decrypt_finalize(decrypt_state_t *state);

#endif