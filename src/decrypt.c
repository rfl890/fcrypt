#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "common.h"
#include "key-derivation.h"

bool decrypt(FILE *input, FILE *output, char *password) {
    EVP_CIPHER_CTX *ctx = NULL;

    uint8_t derived_key[32];
    uint8_t salt[32];
    uint8_t iv[12];
    uint8_t tag[16];
    uint8_t magic[8];

    uint8_t input_buffer[BUFFER_SIZE];
    uint8_t output_buffer[BUFFER_SIZE];

    int outl;

    bool use_chacha20 = false;

    fseek(input, -68, SEEK_END);
    fread(tag, 1, 16, input);
    fread(salt, 1, 32, input);
    fread(iv, 1, 12, input);
    fread(magic, 1, 8, input);
    if (ferror(output)) {
        fprintf(stderr, "error reading input file: %s\n", strerror(errno));
        goto error;
    }
    fseek(input, 0, SEEK_SET);

    if (memcmp(magic, FORMAT_V1_MAGIC_CHACHA, 8) == 0) {
        use_chacha20 = true;
    } else if (memcmp(magic, FORMAT_V1_MAGIC, 8) != 0) {
        fprintf(stderr, "invalid magic\n");
        goto error;
    }

    printf("%s\n", "deriving key...");
    if (!derive_key_from_password(password, strlen(password), salt, NULL,
                                  derived_key)) {
        fprintf(stderr, "error deriving key\n");
        goto error;
    }
    printf("%s\n", "finished deriving key");

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        fprintf(stderr, "EVP_CIPHER_CTX_new error\n");
        goto error;
    }

    if (EVP_DecryptInit_ex(ctx,
                           use_chacha20 ? EVP_chacha20_poly1305()
                                        : EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EVP_DecryptInit_ex (1) error\n");
        goto error;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl error\n");
        goto error;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, derived_key, iv) != 1) {
        fprintf(stderr, "EVP_DecryptInit_ex (2) error\n");
        goto error;
    }

    while (1) {
        size_t bytes_read = fread(input_buffer, 1, BUFFER_SIZE, input);
        bool to_break = false;

        if (bytes_read < BUFFER_SIZE) {
            if (feof(input) && !ferror(input)) {
                to_break = true;
            } else {
                fprintf(stderr, "error reading input file: %s\n",
                        strerror(errno));
                goto error;
            }
        }

        if (EVP_DecryptUpdate(ctx, output_buffer, &outl, input_buffer,
                              to_break ? ((int)bytes_read) - 68
                                       : (int)bytes_read) /* bytes_read <=
                           MAX_BUFFER < INT_MAX*/
            != 1) {
            fprintf(stderr, "%s\n", "EVP_DecryptUpdate error");
            goto error;
        }

        fwrite(output_buffer, 1, to_break ? bytes_read - 68 : bytes_read,
               output);
        if (ferror(output)) {
            fprintf(stderr, "error writing output file: %s\n", strerror(errno));
            goto error;
        }

        if (to_break) {
            break;
        };
    }

    if (EVP_DecryptFinal_ex(ctx, output_buffer, &outl) <= 0) {
        printf("!!! failed to validate tag !!!\nyour encrypted file has been "
               "corrupted and/or tampered with by a 3rd-party.\nalternatively, "
               "you may have just typed the wrong password.\n");
        goto error;
    }

    EVP_CIPHER_CTX_free(ctx);
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