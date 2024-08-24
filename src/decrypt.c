#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "common.h"
#include "crypto.h"

bool decrypt(FILE *input, FILE *output, char *password) {
    uint8_t magic[8];
    uint8_t salt[32];
    uint8_t tag[32];

    fread(magic, 1, 8, input);
    fseek(input, -64, SEEK_END);
    fread(salt, 1, 32, input);
    fread(tag, 1, 32, input);
    if (ferror(output)) {
        eprintf("error reading input file: %s\n", strerror(errno));
        goto error;
    }
    fseek(input, 8, SEEK_SET);

    enum cipher_algorithm algorithm = ALGORITHM_AES;

    if (memcmp(magic, FORMAT_V1_MAGIC_CHACHA, 8) == 0) {
        algorithm = ALGORITHM_CHACHA20;
    } else if (memcmp(magic, FORMAT_V1_MAGIC, 8) != 0) {
        eprintf("invalid magic\n");
        goto error;
    }

    uint8_t input_buffer[BUFFER_SIZE];
    uint8_t output_buffer[BUFFER_SIZE];
    decrypt_state_t state;

    if (!decrypt_init(&state, password, salt, tag, algorithm)) {
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

        if (!decrypt_update(&state, input_buffer,
                            should_break ? ((int)bytes_read) - 64
                                         : (int)bytes_read,
                            output_buffer)) {
            eprintf("%s\n", "EVP_DecryptUpdate error");
            goto error;
        }

        fwrite(output_buffer, 1, should_break ? bytes_read - 64 : bytes_read,
               output);
        if (ferror(output)) {
            eprintf("error writing output file: %s\n", strerror(errno));
            goto error;
        }

        if (should_break)
            break;
    }

    if (!decrypt_finalize(&state)) {
        eprintf("!!! failed to validate tag !!!\nyour encrypted file has been "
                "corrupted and/or tampered with by a "
                "3rd-party.\nalternatively, "
                "you may have just typed the wrong password.\n");
        goto error;
    }

    decrypt_free(&state);
    return true;

error:
    decrypt_free(&state);
    return false;
}