#ifndef DECRYPT_H
#define DECRYPT_H

#include <stdbool.h>
#include <stdio.h>


bool decrypt(FILE *input, FILE *output, char *password);

#endif