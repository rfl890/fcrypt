#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool derive_key_from_password(const char *password, size_t password_size,
                              uint8_t *salt_in, uint8_t *salt_out,
                              uint8_t *derived_out);

#endif