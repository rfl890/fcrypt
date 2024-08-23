#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "crypto.h"

#include <stdbool.h>
#include <stdio.h>


bool encrypt(FILE *input, FILE *output, char *password, enum cipher_algorithm algorithm);

#endif