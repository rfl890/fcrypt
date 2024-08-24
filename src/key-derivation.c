#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <argon2.h>

#include <openssl/rand.h>

// exceeding
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
static const uint32_t ARGON2ID_ITERATIONS = 2;
static const uint32_t ARGON2ID_MEM_COST = 0xffff; // 65536
static const uint32_t ARGON2ID_PARALLELISM = 1;

bool derive_key_from_password(const char *password, size_t password_size,
                              uint8_t *salt_in, uint8_t *salt_out,
                              uint8_t *derived_out) {
    uint8_t salt[32];

    if (salt_in != NULL) {
        memcpy(salt, salt_in, 32);
    } else if (RAND_bytes(salt, 32) != 1) {
        return false;
    }

    if (argon2id_hash_raw(ARGON2ID_ITERATIONS, ARGON2ID_MEM_COST,
                          ARGON2ID_PARALLELISM, password, password_size, salt,
                          32, derived_out, 32) != ARGON2_OK) {
        return false;
    }

    if (salt_out != NULL) {
        memcpy(salt_out, salt, 32);
    }

    return true;
}
