package com.pqaura

/**
 * Kotlin JNI Wrapper for the PQ-Aura Hybrid Post-Quantum Double Ratchet library.
 * This class interfaces directly with the native C/C++ library compiled from Rust.
 */
object PqAuraNative {
    init {
        System.loadLibrary("pq_aura")
    }

    /**
     * Generates a new Hybrid KEM Keypair (X25519 + ML-KEM-1024).
     * @return JSON String: { "public_key": [Bytes], "secret_key": [Bytes] }
     */
    external fun generateKeypair(): String

    /**
     * Generates a new Hybrid Signature Keypair (Ed25519 + ML-DSA-65).
     * @return JSON String: { "verifying_key": [Bytes], "signing_key": [Bytes] }
     */
    external fun generateSigningKeypair(): String

    /**
     * Creates a signed Pre-Key Bundle.
     * @param identityPk Raw bytes of Bob's identity hybrid public key.
     * @param signingKey Raw bytes of Bob's hybrid signing secret key.
     * @return JSON String representation of Bob's PreKeyBundle.
     */
    external fun createBundle(identityPk: ByteArray, signingKey: ByteArray): String

    /**
     * Initiates a session as Alice (the sender).
     * @param remoteBundleJson JSON string of Bob's fetched PreKeyBundle.
     * @param localIdentityPk Raw bytes of Alice's hybrid identity public key.
     * @param localIdentitySk Raw bytes of Alice's hybrid identity secret key.
     * @return JSON String containing: { "state_ptr": Long, "initial_message": {...} }
     */
    external fun initAlice(
        remoteBundleJson: String,
        localIdentityPk: ByteArray,
        localIdentitySk: ByteArray
    ): String

    /**
     * Responds to an initiation message as Bob (the receiver).
     * @param initialMsgJson JSON string of Alice's InitialMessage.
     * @param localIdentityPk Bob's identity public key.
     * @param localIdentitySk Bob's identity secret key.
     * @param localSignedSk Bob's signed pre-key secret key.
     * @param localOtSk Bob's one-time prekey secret key (optional).
     * @param hasOtSk True if localOtSk is provided.
     * @return Long: Raw pointer to the instantiated RatchetState.
     */
    external fun respondBob(
        initialMsgJson: String,
        localIdentityPk: ByteArray,
        localIdentitySk: ByteArray,
        localSignedSk: ByteArray,
        localOtSk: ByteArray,
        hasOtSk: Boolean
    ): Long

    /**
     * Encrypts a plaintext message.
     * @param statePtr Raw pointer to the RatchetState.
     * @param plaintext Plaintext message bytes.
     * @param ad Associated data bytes.
     * @return JSON String containing the encrypted message header and payload.
     */
    external fun encrypt(
        statePtr: Long,
        plaintext: ByteArray,
        ad: ByteArray
    ): String

    /**
     * Decrypts a ciphertext message.
     * @param statePtr Raw pointer to the RatchetState.
     * @param header Ciphertext header bytes.
     * @param payload Ciphertext payload bytes.
     * @param ad Associated data bytes.
     * @return ByteArray containing decrypted plaintext, or null if decryption fails.
     */
    external fun decrypt(
        statePtr: Long,
        header: ByteArray,
        payload: ByteArray,
        ad: ByteArray
    ): ByteArray?

    /**
     * Reconstructs a RatchetState from its serialized JSON form.
     * @param serializedState JSON bytes of the serialized state.
     * @return Long: Raw pointer to the RatchetState.
     */
    external fun initState(serializedState: ByteArray): Long

    /**
     * Loads a RatchetState from an atomically encrypted file.
     * @param path Full file path string.
     * @param key 32-byte symmetric decryption key.
     * @return Long: Raw pointer to the RatchetState.
     */
    external fun loadAtomic(path: String, key: ByteArray): Long

    /**
     * Atomically encrypts and writes the RatchetState to a file.
     * @param statePtr Raw pointer to the RatchetState.
     * @param path Full file path string.
     * @param key 32-byte symmetric encryption key.
     * @return Boolean: True if successful, false otherwise.
     */
    external fun saveAtomic(statePtr: Long, path: String, key: ByteArray): Boolean

    /**
     * Frees the RatchetState memory block in native RAM and zeroizes secret components.
     * @param statePtr Raw pointer to the RatchetState.
     */
    external fun freeState(statePtr: Long)
}
