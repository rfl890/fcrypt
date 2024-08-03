#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stdbool.h>
#include <stdio.h>


bool encrypt(FILE *input, FILE *output, char *password, bool use_chacha);

#endif