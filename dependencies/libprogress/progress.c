#include "progress.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VALIDATE_RETURN(expr, ret) \
    do {                           \
        if (!(expr)) {             \
            return ret;            \
        }                          \
    } while (0);

int progress_init(progress_state_t *state, int64_t total, size_t bar_length,
                  char *label, char fill, char tip, char start, char end,
                  int show_percentage) {
    VALIDATE_RETURN(state != NULL, 1)
    VALIDATE_RETURN(label != NULL, 1)
    VALIDATE_RETURN(bar_length >= 1, 1)
    VALIDATE_RETURN(total >= 0, 1)

    state->current_progress = 0;

    state->total_progress = total;
    state->bar_length = bar_length;

    state->progress_fill = fill;
    state->progress_tip = tip;

    // Bar length (amount of fill characters) + 2 edge characters + null
    state->buffer_size = bar_length + 3;

    if ((state->buffer = malloc(state->buffer_size)) == NULL) {
        return 1;
    }

    if ((state->label = malloc(strlen(label) + 1)) == NULL) {
        free(state->buffer);
        return 1;
    }

    memcpy(state->label, label, strlen(label) + 1);

    state->buffer[0] = start;
    for (size_t i = 1; i <= state->buffer_size - 3; i++) {
        state->buffer[i] = ' ';
    }

    state->buffer[state->buffer_size - 2] = end;
    state->buffer[state->buffer_size - 1] = 0x00;

    state->last_chars_filled = -1;
    state->last_percentage = -1;

    state->finalized = 0;
    state->show_percentage = show_percentage;

    fputs(state->buffer, stdout);
    putchar('\r');
    fflush(stdout);

    return 0;
}

void progress_update(progress_state_t *state, int64_t amount) {
    state->current_progress += amount;

    if (state->current_progress < 0) {
        state->current_progress = 0;
    }
    if (state->current_progress > state->total_progress) {
        state->current_progress = state->total_progress;
    }

    int64_t chars_to_fill =
        (state->current_progress * state->bar_length) / state->total_progress;
    int64_t percentage =
        (state->current_progress * 100) / state->total_progress;

    if (state->show_percentage) {
        if (percentage <= state->last_percentage) return;
    } else if (chars_to_fill <= state->last_chars_filled) {
        return;
    };

    state->last_chars_filled = chars_to_fill;
    state->last_percentage = percentage;

    for (size_t i = 1; i <= chars_to_fill; i++) {
        state->buffer[i] = state->progress_fill;
    }

    if ((chars_to_fill < state->bar_length) && state->progress_tip != '\x00') {
        state->buffer[chars_to_fill + 1] = state->progress_tip;
    }

    fputs(state->label, stdout);
    fputs(state->buffer, stdout);
    if (state->show_percentage) {
        printf(" %lli%%", percentage);
    }
    putchar('\r');
    fflush(stdout);
}

void progress_set(progress_state_t *state, int64_t value) {
    state->current_progress = value;

    // to force a redraw
    state->last_chars_filled = -1;
    state->last_percentage = -1;

    // clear the buffer
    for (size_t i = 1; i <= state->buffer_size - 3; i++) {
        state->buffer[i] = ' ';
    }

    // clear the line
    for (size_t i = 0; i < state->buffer_size + 4 /* possible percentage */;
         i++) {
        putchar(' ');
    }
    putchar('\r');

    progress_update(state, 0);
}

void progress_final(progress_state_t *state) {
    if (state->finalized == 0) {
        state->finalized = 1;
        free(state->buffer);
        free(state->label);
        putchar('\n');
    }
}