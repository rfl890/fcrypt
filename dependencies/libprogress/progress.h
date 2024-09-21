#ifndef ___LIBPROGRESS_H___
#define ___LIBPROGRESS_H___

#include <stddef.h>
#include <stdint.h>

typedef struct _progress_state {
    size_t bar_length;

    int64_t current_progress;
    int64_t total_progress;

    char progress_fill;
    char progress_tip;

    char *buffer;
    size_t buffer_size;

    char *label;

    int64_t last_chars_filled;
    int64_t last_percentage;

    char finalized;

    int show_percentage;
} progress_state_t;

int progress_init(progress_state_t *state, int64_t total, size_t bar_length,
                  char *label, char fill, char tip, char start, char end,
                  int show_percentage);
void progress_update(progress_state_t *state, int64_t amount);
void progress_set(progress_state_t *state, int64_t value);
void progress_final(progress_state_t *state);

#endif