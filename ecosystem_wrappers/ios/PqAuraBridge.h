#ifndef PqAuraBridge_h
#define PqAuraBridge_h

#include <stdint.h>
#include <stdbool.h>

// Opaque structure matching RatchetState
typedef struct RatchetState RatchetState;

typedef struct {
    uint8_t *header;
    uintptr_t header_len;
    uint8_t *payload;
    uintptr_t payload_len;
} FfiMessage;

typedef struct {
    RatchetState *state_ptr;
    uint8_t *alice_identity_pk;
    uintptr_t alice_identity_pk_len;
    uint8_t *ephemeral_pk;
    uintptr_t ephemeral_pk_len;
    uint8_t *kem_ciphertext_identity;
    uintptr_t kem_ciphertext_identity_len;
    uint8_t *kem_ciphertext_signed;
    uintptr_t kem_ciphertext_signed_len;
    uint8_t *kem_ciphertext_one_time;
    uintptr_t kem_ciphertext_one_time_len;
    bool has_one_time;
    uint8_t *ratchet_message_header;
    uintptr_t ratchet_message_header_len;
    uint8_t *ratchet_message_payload;
    uintptr_t ratchet_message_payload_len;
} FfiInitialMessage;

FfiInitialMessage* pqa_init_alice(
    const uint8_t *remote_bundle_ptr, uintptr_t remote_bundle_len,
    const uint8_t *local_identity_pk_ptr, uintptr_t local_identity_pk_len,
    const uint8_t *local_identity_sk_ptr, uintptr_t local_identity_sk_len
);

RatchetState* pqa_init_bob(
    const uint8_t *initial_msg_ptr, uintptr_t initial_msg_len,
    const uint8_t *local_identity_pk_ptr, uintptr_t local_identity_pk_len,
    const uint8_t *local_identity_sk_ptr, uintptr_t local_identity_sk_len,
    const uint8_t *local_signed_sk_ptr, uintptr_t local_signed_sk_len,
    const uint8_t *local_ot_sk_ptr, uintptr_t local_ot_sk_len,
    bool has_ot_sk
);

FfiMessage* pqa_encrypt(
    RatchetState *state_ptr,
    const uint8_t *plaintext_ptr, uintptr_t plaintext_len,
    const uint8_t *ad_ptr, uintptr_t ad_len
);

uint8_t* pqa_decrypt(
    RatchetState *state_ptr,
    const uint8_t *header_ptr, uintptr_t header_len,
    const uint8_t *payload_ptr, uintptr_t payload_len,
    const uint8_t *ad_ptr, uintptr_t ad_len,
    uintptr_t *out_len
);

bool pqa_save_atomic(
    const RatchetState *state_ptr,
    const char *path_ptr,
    const uint8_t *key_ptr
);

RatchetState* pqa_load_atomic(
    const char *path_ptr,
    const uint8_t *key_ptr
);

void pqa_free_message(FfiMessage *msg_ptr);
void pqa_free_buffer(uint8_t *ptr, uintptr_t len);
void pqa_free_initial_message(FfiInitialMessage *msg_ptr);
void pqa_free_state(RatchetState *state_ptr);

#endif /* PqAuraBridge_h */
