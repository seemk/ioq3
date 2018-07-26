#include <stdlib.h>
#include <string.h>
#include "q_queue.h"

static int32_t q_queue_full(const q_queue* q) {
  if (q->length == q->capacity) {
    return 1;
  }

  return 0;
}

q_queue* q_queue_create(int32_t item_size) {
  q_queue* q = (q_queue*)calloc(1, sizeof(q_queue));
  q_queue_init(q, item_size);
  return q;
}

void q_queue_init(q_queue* q, int32_t item_size) {
  memset(q, 0, sizeof(q_queue));
  q->item_size = item_size;
  q->capacity = 32;
  q->items = (uint8_t*)calloc(q->capacity, item_size);
}

void q_queue_push(q_queue* q, const void* item) {
  if (q_queue_full(q)) {
    int32_t new_cap = q->capacity * 1.5;
    uint8_t* new_items = (uint8_t*)calloc(new_cap, q->item_size);

    int32_t n_upper = q->length - q->start;
    int32_t n_lower = q->length - n_upper;
    memcpy(new_items, q->items + q->start * q->item_size,
           q->item_size * n_upper);
    memcpy(new_items + q->item_size * n_upper, q->items,
           q->item_size * n_lower);

    free(q->items);

    q->start = 0;
    q->capacity = new_cap;
    q->items = new_items;
  }

  const int32_t insert_idx =
      ((q->start + q->length) % q->capacity) * q->item_size;
  memcpy(q->items + insert_idx, item, q->item_size);
  q->length++;
}

int32_t q_queue_pop(q_queue* q, void* item) {
  if (q->length > 0) {
    memcpy(item, q->items + q->start * q->item_size, q->item_size);
    q->start = (q->start + 1) % q->capacity;
    q->length--;
    return 1;
  }

  return 0;
}
