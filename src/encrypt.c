#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "common.h"
#include "key-derivation.h"

bool encrypt(FILE *input, FILE *output, char *password, bool use_chacha) {
    EVP_CIPHER_CTX *ctx = NULL;

    uint8_t derived_key[32];
    uint8_t salt[32];
    uint8_t iv[8];

    uint8_t input_buffer[BUFFER_SIZE];
    uint8_t output_buffer[BUFFER_SIZE];

    int outl;

    if (RAND_bytes(iv, 8) != 1) {
        fprintf(stderr, "error filling random bytes for IV\n");
        return false;
    }

    if (use_chacha) {
        fprintf(stderr, "%s\n", "using ChaCha20-Poly1305");
    }
    fprintf(stderr, "%s\n", "deriving key...");
    if (!derive_key_from_password(password, strlen(password), NULL, salt,
                                 derived_key)) {
        fprintf(stderr, "error deriving key\n");
        goto error;
    }
    fprintf(stderr, "%s\n", "finished deriving key");

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        fprintf(stderr, "EVP_CIPHER_CTX_new error\n");
        goto error;
    }

    if (EVP_EncryptInit_ex(ctx, use_chacha ? EVP_chacha20_poly1305() : EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (1) error\n");
        goto error;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 8, NULL) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl (1) error\n");
        goto error;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, derived_key, iv) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (2) error\n");
        goto error;
    }

    fwrite(use_chacha ? FORMAT_V1_MAGIC_CHACHA : FORMAT_V1_MAGIC, 1, 8, output);

    while (1) {
        size_t bytes_read = fread(input_buffer, 1, BUFFER_SIZE, input);
        bool should_break = false;

        if (bytes_read < BUFFER_SIZE) {
            if (feof(input) && !ferror(input)) {
                should_break = true;
            } else {
                fprintf(stderr, "error reading input file: %s\n",
                        strerror(errno));
                goto error;
            }
        }

        if (EVP_EncryptUpdate(ctx, output_buffer, &outl, input_buffer,
                              (int)bytes_read) /* bytes_read <= MAX_BUFFER <
                                                  INT_MAX*/
            != 1) {
            fprintf(stderr, "%s\n", "EVP_EncryptUpdate error");
            goto error;
        }

        fwrite(output_buffer, 1, bytes_read, output);
        if (ferror(output)) {
            fprintf(stderr, "error writing output file: %s\n", strerror(errno));
            goto error;
        }

        if (should_break) {
            break;
        };
    }

    if (EVP_EncryptFinal_ex(ctx, output_buffer, &outl) !=
        1) { /* outl will be set to 0 */
        fprintf(stderr, "%s\n", "EVP_EncryptFinal_ex error");
        goto error;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, output_buffer) !=
        1) {
        fprintf(stderr, "%s\n", "EVP_CIPHER_CTX_ctrl (2) error");
        goto error;
    }

    EVP_CIPHER_CTX_free(ctx);

    fseek(output, 0, SEEK_END);
    fwrite(output_buffer, 1, 16, output);
    fwrite(salt, 1, 32, output);
    fwrite(iv, 1, 8, output);
    if (ferror(output)) {
        fprintf(stderr, "error writing output file: %s\n", strerror(errno));
        goto error;
    }
    
    OPENSSL_cleanse(derived_key, 32);
    OPENSSL_cleanse(input_buffer, 32);
    OPENSSL_cleanse(output_buffer, 32);
    return true;

error:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }

    OPENSSL_cleanse(derived_key, 32);
    OPENSSL_cleanse(input_buffer, 32);
    OPENSSL_cleanse(output_buffer, 32);
    return false;
}