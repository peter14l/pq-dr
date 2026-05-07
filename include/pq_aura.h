#ifndef PQ_AURA_H
#define PQ_AURA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RatchetState RatchetState;

typedef struct {
    uint8_t *header;
    size_t header_len;
    uint8_t *payload;
    size_t payload_len;
} FfiMessage;

typedef struct {
    uint8_t *public_key;
    size_t public_key_len;
    uint8_t *secret_key;
    size_t secret_key_len;
} FfiKeyPair;

// Decryption
uint8_t* pqa_decrypt(
    RatchetState *state_ptr,
    const uint8_t *header_ptr,
    size_t header_len,
    const uint8_t *payload_ptr,
    size_t payload_len,
    const uint8_t *ad_ptr,
    size_t ad_len,
    size_t *out_len
);

// Memory Management
void pqa_free_message(FfiMessage *msg_ptr);
void pqa_free_buffer(uint8_t *ptr, size_t len);

// State Management
RatchetState* pqa_deserialize_state(const uint8_t *bytes, size_t len);
void pqa_free_state(RatchetState *state);

#ifdef __cplusplus
}
#endif

#endif // PQ_AURA_H
