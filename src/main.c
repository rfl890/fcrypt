#include <cmake-generated.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>


#include "decrypt.h"
#include "encrypt.h"

const char *version_str = "fcrypt 0.1\n"
                          "git %s\n"
                          "compiler: %s %s\n"
                          "avx2 optimizations: %s\n";

const char *help_string = "usage: fcrypt --decrypt -chacha20 --password PASSWORD "
                          "--input INPUT --output OUTPUT\n"
                          "flags:\n\n"
                          "--chacha20, -c            Use ChaCha20-Poly1305 (for "
                          "devices without AES-NI)\n"
                          "--decrypt,  -d            Decrypt mode\n"
                          "--help,     -h            Show this message\n"
                          "--version,  -v            Show version\n"
                          "\n"
                          "--password, -p            Password\n"
                          "--input,    -i            Input file\n"
                          "--output,   -o            Output file\n";

static struct option options[] = {{"chacha20", optional_argument, NULL, 'c'},
                                  {"decrypt", optional_argument, NULL, 'd'},
                                  {"help", optional_argument, NULL, '?'},
                                  {"version", optional_argument, NULL, 'v'},
                                  {"password", required_argument, NULL, 'p'},
                                  {"input", required_argument, NULL, 'i'},
                                  {"output", required_argument, NULL, 'o'}};

int main(int argc, char *const *argv) {
    int opt;

    char *input_filename = NULL;
    char *output_filename = NULL;
    char *password = NULL;

    bool flg_decrypt = false;
    bool flg_chacha20 = false;
    bool show_help = false;
    bool show_version = false;
    bool error = false;

    while ((opt = getopt_long(argc, argv, "p:i:o:dchv", options, NULL)) != -1) {
        switch (opt) {
        case 'p':
            password = optarg;
            break;
        case 'i':
            input_filename = optarg;
            break;
        case 'o':
            output_filename = optarg;
            break;
        case 'd':
            flg_decrypt = true;
            break;
        case 'c':
            flg_chacha20 = true;
            break;
        case 'h':
            show_help = true;
            break;
        case 'v':
            show_version = true;
            break;
        case ':':
            error = true;
            break;
        case '?':
            error = true;
            break;
        default:
            error = true;
            break;
        }
    }

    if (show_version) {
        printf(version_str, GIT_COMMIT_HASH, COMPILER_STR, COMPILER_VERSION_STR, BUILD_X86_64_V3 ? "yes" : "no");
        return 0;
    }
    if (show_help) {
        printf("%s", help_string);
        return 0;
    }

    if ((password == NULL) && (error == false)) {
        fprintf(stderr, "missing required argument -p\n");
        error = true;
    }
    if ((input_filename == NULL) && (error == false)) {
        fprintf(stderr, "missing required argument -i\n");
        error = true;
    }
    if ((output_filename == NULL) && (error == false)) {
        fprintf(stderr, "missing required argument -o\n");
        error = true;
    }

    if (error) {
        fprintf(stderr, help_string, argv[0]);
        return EXIT_FAILURE;
    }

    FILE *input_file = fopen(input_filename, "rb");
    if (input_file == NULL) {
        fprintf(stderr, "error opening input file %s: %s\n", input_filename,
                strerror(errno));
        return EXIT_FAILURE;
    }

    FILE *output_file = fopen(output_filename, "wb");
    if (output_file == NULL) {
        fprintf(stderr, "error opening output file %s: %s\n", output_filename,
                strerror(errno));
        return EXIT_FAILURE;
    }

    if (flg_decrypt) {
        bool result = decrypt(input_file, output_file, password);
        fclose(input_file);
        fclose(output_file);
        if (result) {
            printf("file decryption completed successfully\n");
        } else {
            printf("file decryption failed\n");
            return EXIT_FAILURE;
        }
    } else {
        bool result = encrypt(input_file, output_file, password, flg_chacha20);
        fclose(input_file);
        fclose(output_file);
        if (!result) {
            printf("errors occured, file encryption incomplete!\nthe output "
                   "file is in a corrupt state and should be deleted\n");
            return EXIT_FAILURE;
        } else {
            printf("file encryption successfully completed\n");
        }
    }

    return EXIT_SUCCESS;
}