#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <blake3.h>

#include "common.h"
#include "crypto.h"
#include "key-derivation.h"

static const char *context_encryption = "fcrypt v1.1 [encryption key]";
static const char *context_hmac = "fcrypt v1.1 [hmac key]";

void encrypt_free(encrypt_state_t *state) {
    if (state->ctx != NULL) {
        EVP_CIPHER_CTX_free(state->ctx);
    }

    OPENSSL_cleanse(state, sizeof(encrypt_state_t));
}

bool encrypt_init(encrypt_state_t *state, const char *password,
                  enum cipher_algorithm algorithm) {

    // Key derivation
    eprintf("%s\n", "deriving key...");
    if (!derive_key_from_password(password, strlen(password), NULL, state->salt,
                                  state->derived_key)) {
        eprintf("error deriving key\n");
    }
    eprintf("%s\n", "finished deriving key");

    blake3_hasher_init_derive_key(&state->hasher, context_encryption);
    blake3_hasher_update(&state->hasher, state->derived_key, 32);
    blake3_hasher_finalize(&state->hasher, state->encryption_key, 32);

    blake3_hasher_init_derive_key(&state->hasher, context_hmac);
    blake3_hasher_update(&state->hasher, state->derived_key, 32);
    blake3_hasher_finalize(&state->hasher, state->hmac_key, 32);

    blake3_hasher_init_keyed(&state->hasher, state->hmac_key);

    // State initialization
    const EVP_CIPHER *cipher;

    /* We use an all-zero counter. */
    uint8_t counter[16];
    OPENSSL_cleanse(counter, 16);

    switch (algorithm) {
    case ALGORITHM_AES:
        cipher = EVP_aes_256_ctr();
        break;
    case ALGORITHM_CHACHA20:
        cipher = EVP_chacha20();
        break;
    default:
        cipher = EVP_aes_256_ctr();
        break;
    }

    if ((state->ctx = EVP_CIPHER_CTX_new()) == NULL) {
        eprintf("EVP_CIPHER_CTX_new error\n");
        goto error;
    }
    if (EVP_EncryptInit_ex(state->ctx, cipher, NULL, state->derived_key,
                           counter) != 1) {
        eprintf("EVP_EncryptInit_ex error\n");
        goto error;
    }

    return true;

error:
    return false;
}

bool encrypt_update(encrypt_state_t *state, void *input, int input_length,
                    void *output) {
    int outl;

    if (EVP_EncryptUpdate(state->ctx, output, &outl, input, input_length) !=
        1) {
        eprintf("%s\n", "EVP_EncryptUpdate error");
        goto error;
    }
    blake3_hasher_update(&state->hasher, output, input_length);

    return true;

error:
    return false;
}

void encrypt_finalize(encrypt_state_t *state, uint8_t *tag_out,
                      uint8_t *salt_out) {
    int outl;
    // nothing will happen to this buffer
    uint8_t buffer[1];
    EVP_EncryptFinal(state->ctx, buffer, &outl);

    blake3_hasher_finalize(&state->hasher, tag_out, 32);
    memcpy(salt_out, state->salt, 32);
}