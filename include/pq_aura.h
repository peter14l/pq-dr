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

typedef struct {
    uint8_t *identity_pk;
    size_t identity_pk_len;
    uint8_t *signed_pre_key;
    size_t signed_pre_key_len;
    uint8_t *one_time_pre_key;
    size_t one_time_pre_key_len;
    bool has_one_time;
} FfiPreKeyBundle;

typedef struct {
    RatchetState *state_ptr;
    uint8_t *alice_identity_pk;
    size_t alice_identity_pk_len;
    uint8_t *ephemeral_pk;
    size_t ephemeral_pk_len;
    uint8_t *kem_ciphertext_identity;
    size_t kem_ciphertext_identity_len;
    uint8_t *kem_ciphertext_signed;
    size_t kem_ciphertext_signed_len;
    uint8_t *kem_ciphertext_one_time;
    size_t kem_ciphertext_one_time_len;
    bool has_one_time;
    uint8_t *ratchet_message_header;
    size_t ratchet_message_header_len;
    uint8_t *ratchet_message_payload;
    size_t ratchet_message_payload_len;
} FfiInitialMessage;

// Key Management
FfiKeyPair* pqa_generate_keypair();
void pqa_free_keypair(FfiKeyPair *kp_ptr);
FfiPreKeyBundle* pqa_create_bundle(const uint8_t *identity_pk_ptr, size_t identity_pk_len);
void pqa_free_bundle(FfiPreKeyBundle *bundle_ptr);

// Handshake
FfiInitialMessage* pqa_init_alice(
    const uint8_t *remote_bundle_ptr,
    size_t remote_bundle_len,
    const uint8_t *local_identity_pk_ptr,
    size_t local_identity_pk_len,
    const uint8_t *local_identity_sk_ptr,
    size_t local_identity_sk_len
);

RatchetState* pqa_init_bob(
    const uint8_t *initial_msg_ptr,
    size_t initial_msg_len,
    const uint8_t *local_identity_pk_ptr,
    size_t local_identity_pk_len,
    const uint8_t *local_identity_sk_ptr,
    size_t local_identity_sk_len,
    const uint8_t *local_signed_sk_ptr,
    size_t local_signed_sk_len,
    const uint8_t *local_ot_sk_ptr,
    size_t local_ot_sk_len,
    bool has_ot_sk
);

// Encryption & Decryption
FfiMessage* pqa_encrypt(
    RatchetState *state_ptr,
    const uint8_t *plaintext_ptr,
    size_t plaintext_len,
    const uint8_t *ad_ptr,
    size_t ad_len
);

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
void pqa_free_initial_message(FfiInitialMessage *msg_ptr);

// State Management
uint8_t* pqa_serialize_state(const RatchetState *state_ptr);
size_t pqa_serialize_state_len(const RatchetState *state_ptr);
RatchetState* pqa_deserialize_state(const uint8_t *bytes, size_t len);
void pqa_free_state(RatchetState *state);

// Atomic State Persistence
bool pqa_save_atomic(const RatchetState *state_ptr, const char *path_ptr, const uint8_t *key_ptr);
RatchetState* pqa_load_atomic(const char *path_ptr, const uint8_t *key_ptr);

#ifdef __cplusplus
}
#endif

#endif // PQ_AURA_H
