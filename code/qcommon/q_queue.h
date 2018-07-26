#pragma once

#include <stdint.h>

typedef struct {
  int32_t item_size;
  int32_t start;
  int32_t length;
  int32_t capacity;
  uint8_t* items;
} q_queue;

q_queue* q_queue_create(int32_t item_size);
void q_queue_init(q_queue* q, int32_t item_size);
void q_queue_push(q_queue* q, const void* item);
int32_t q_queue_pop(q_queue* q, void* item);
