#ifndef PARSE_ARGS_H
#define PARSE_ARGS_H

#include <stdio.h>
#include <stdbool.h>

#include "crypto.h"

enum fcrypt_operation {
    FCRYPT_ENCRYPT,
    FCRYPT_DECRYPT
};

struct fcrypt_args {
    FILE *input_file;
    FILE *output_file;

    char *password;

    enum fcrypt_operation operation;
    enum cipher_algorithm algorithm;
};

struct fcrypt_args parse_args(int argc, const char **argv);

#endif