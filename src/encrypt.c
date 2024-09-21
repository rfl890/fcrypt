#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "common.h"
#include "crypto.h"

#include "progress.h"

bool encrypt(FILE *input, FILE *output, char *password,
             enum cipher_algorithm algorithm) {
    char *magic;
    switch (algorithm) {
    case ALGORITHM_AES:
        magic = FORMAT_V1_MAGIC;
        break;
    case ALGORITHM_CHACHA20:
        magic = FORMAT_V1_MAGIC_CHACHA;
        break;
    default:
        magic = FORMAT_V1_MAGIC;
        break;
    }

    fwrite(magic, 1, 8, output);
    if (ferror(output) != 0) {
        eprintf("error writing output file: %s\n", strerror(errno));
        goto error;
    }

    uint8_t input_buffer[BUFFER_SIZE];
    uint8_t output_buffer[BUFFER_SIZE];
    encrypt_state_t state;

    if (!encrypt_init(&state, password, algorithm)) {
        goto error;
    }

    while (1) {
        size_t bytes_read = fread(input_buffer, 1, BUFFER_SIZE, input);
        bool should_break = false;

        if (bytes_read < BUFFER_SIZE) {
            if (feof(input) && !ferror(input)) {
                should_break = true;
            } else {
                eprintf("error reading input file: %s\n", strerror(errno));
                goto error;
            }
        }

        if (!encrypt_update(&state, input_buffer, (int)bytes_read,
                            output_buffer)) {
            goto error;
        }

        fwrite(output_buffer, 1, bytes_read, output);
        if (ferror(output)) {
            eprintf("error writing output file: %s\n", strerror(errno));
            goto error;
        }

        if (should_break)
            break;
    }

    uint8_t tag[32];
    uint8_t salt[32];
    encrypt_finalize(&state, tag, salt);
    encrypt_free(&state);

    fseek(output, 0, SEEK_END);
    fwrite(salt, 1, 32, output);
    fwrite(tag, 1, 32, output);

    return true;

error:
    encrypt_free(&state);
    return false;
}