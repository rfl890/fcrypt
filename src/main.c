#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "decrypt.h"
#include "encrypt.h"
#include "parse-args.h"

int main(int argc, const char **argv) {
    struct fcrypt_args args = parse_args(argc, argv);

    switch (args.operation) {
    case FCRYPT_ENCRYPT: {
        bool result = encrypt(args.input_file, args.output_file, args.password,
                              args.use_chacha20);
        fclose(args.input_file);
        fclose(args.output_file);
        if (!result) {
            fprintf(stderr,
                    "errors occured, file encryption incomplete!\nthe output "
                    "file is in a corrupt state and should be deleted\n");
            return EXIT_FAILURE;
        } else {
            fprintf(stderr, "file encryption successfully completed\n");
        }
        break;
    }
    case FCRYPT_DECRYPT: {
        bool result = decrypt(args.input_file, args.output_file, args.password);
        fclose(args.input_file);
        fclose(args.output_file);
        if (result) {
            fprintf(stderr, "file decryption completed successfully\n");
        } else {
            fprintf(stderr, "file decryption failed\n");
            return EXIT_FAILURE;
        }
        break;
    }
    }

    return EXIT_SUCCESS;
}