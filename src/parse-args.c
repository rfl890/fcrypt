#include <string.h>
#ifdef CMAKE_COMPILING
#include <cmake-generated.h>
#endif
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>

#include "common.h"
#include "parse-args.h"

struct fcrypt_flags {
    bool flg_chacha20;
    bool flg_decrypt;
    bool flg_help;
    bool flg_version;
};

const char *version_string = "fcrypt 1.1\n"
                             "git %s\n"
                             "compiler: %s %s\n";

const char *usage_string =
    "usage: fcrypt --decrypt -chacha20 --password PASSWORD "
    "--input INPUT --output OUTPUT\n";

const char *help_string =
    "flags:\n\n"
    "--use-chacha20, -c        Use ChaCha20-Poly1305 (for "
    "devices without AES-NI)\n"
    "--decrypt,      -d        Decrypt mode\n"
    "--help,         -h        Show this message\n"
    "--version,      -v        Show version\n"
    "\n"
    "--password,     -p        Password\n"
    "--input,        -i        Input file\n"
    "--output,       -o        Output file\n";

static struct option options[] = {{"use-chacha20", optional_argument, NULL,
                                   'c'},
                                  {"decrypt", optional_argument, NULL, 'd'},
                                  {"help", optional_argument, NULL, 'h'},
                                  {"version", optional_argument, NULL, 'v'},
                                  {"password", required_argument, NULL, 'p'},
                                  {"input", required_argument, NULL, 'i'},
                                  {"output", required_argument, NULL, 'o'},
                                  {NULL, 0, NULL, 0}};

struct fcrypt_args parse_args(int argc, const char **argv) {
    int opt;

    struct fcrypt_args args = {.password = NULL,
                               .input_file = NULL,
                               .output_file = NULL,

                               .operation = FCRYPT_ENCRYPT,
                               .algorithm = ALGORITHM_AES};
    struct fcrypt_flags flags = {.flg_chacha20 = false,
                                 .flg_decrypt = false,
                                 .flg_help = false,
                                 .flg_version = false};

    char *input_filename = NULL;
    char *output_filename = NULL;

    bool error = false;

    while ((opt = getopt_long(argc, (char *const *)argv, "p:i:o:dchv", options,
                              NULL)) != -1) {
        switch (opt) {
        case 'p':
            args.password = optarg;
            break;
        case 'i':
            input_filename = optarg;
            break;
        case 'o':
            output_filename = optarg;
            break;
        case 'd':
            flags.flg_decrypt = true;
            break;
        case 'c':
            flags.flg_chacha20 = true;
            break;
        case 'h':
            flags.flg_help = true;
            break;
        case 'v':
            flags.flg_version = true;
            break;
        case '?':
            error = true;
            break;
        default:
            error = true;
            break;
        }
    }

    // Handle help/version information
    if (flags.flg_help && flags.flg_version) {
        eprintf("%s\n",
                "error: flags '--help' and '--version' are mutually "
                "exclusive\n");
        exit(EXIT_FAILURE);
    }

    if (flags.flg_help) {
        eprintf("%s%s", usage_string, help_string);
        exit(EXIT_SUCCESS);
    } else if (flags.flg_version) {
#ifdef CMAKE_COMPILING
        eprintf(version_string, GIT_COMMIT_HASH, COMPILER_STR,
                COMPILER_VERSION_STR);
        exit(EXIT_SUCCESS);
#endif
    }

    // Check required args
    if (args.password == NULL) {
        eprintf("missing required argument --password\n"
                        "try running with --help for more info\n");
        exit(EXIT_FAILURE);
    }
    if (input_filename == NULL) {
        eprintf("missing required argument --input\n"
                        "try running with --help for more info\n");
        exit(EXIT_FAILURE);
    }
    if (output_filename == NULL) {
        eprintf("missing required argument --output\n"
                        "try running with --help for more info\n");
        exit(EXIT_FAILURE);
    }

    if (error) {
        eprintf("%s", usage_string);
        eprintf("%s\n", "try running with --help for more info\n");
        exit(EXIT_FAILURE);
    }

    // Check optional args
    if (flags.flg_chacha20) {
        args.algorithm = ALGORITHM_CHACHA20;
    }
    if (flags.flg_decrypt) {
        args.operation = FCRYPT_DECRYPT;
    }

    // Set files
    if (strcmp(input_filename, "-") == 0) {
        args.input_file = stdin;
    }
    if (strcmp(output_filename, "-") == 0) {
        args.output_file = stdout;
    }

    if (args.input_file == NULL) {
        FILE *input_file = fopen(input_filename, "rb");
        if (input_file == NULL) {
            eprintf("error opening input file %s: %s\n", input_filename,
                    strerror(errno));
            exit(EXIT_FAILURE);
        }
        args.input_file = input_file;
    }
    if (args.output_file == NULL) {
        FILE *output_file = fopen(output_filename, "wb");
        if (output_file == NULL) {
            eprintf("error opening output file %s: %s\n",
                    output_filename, strerror(errno));
            exit(EXIT_FAILURE);
        }
        args.output_file = output_file;
    }

    return args;
}