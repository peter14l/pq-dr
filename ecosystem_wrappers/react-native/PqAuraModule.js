import { NativeModules, Platform } from 'react-native';

const { PqAuraBridgeModule } = NativeModules;

/**
 * JS wrapper for React Native bridging of the PQ-Aura Hybrid Post-Quantum Double Ratchet.
 * Delegates execution to PqAuraNative (Android JNI) and PqAuraClient (iOS Swift).
 */
class PqAuraModule {
  /**
   * Generates a new hybrid KEM keypair (X25519 + ML-KEM-1024).
   * @returns {Promise<{publicKey: string, secretKey: string}>} Base64 encoded keys.
   */
  static async generateKeypair() {
    const res = await PqAuraBridgeModule.generateKeypair();
    return JSON.parse(res);
  }

  /**
   * Generates a new hybrid signature keypair (Ed25519 + ML-DSA-65).
   * @returns {Promise<{verifyingKey: string, signingKey: string}>} Base64 encoded keys.
   */
  static async generateSigningKeypair() {
    const res = await PqAuraBridgeModule.generateSigningKeypair();
    return JSON.parse(res);
  }

  /**
   * Creates a signed prekey bundle.
   * @param {string} identityPk Base64 encoded hybrid identity public key.
   * @param {string} signingKey Base64 encoded hybrid signing secret key.
   * @returns {Promise<object>} JSON representing the signed PreKeyBundle.
   */
  static async createBundle(identityPk, signingKey) {
    const res = await PqAuraBridgeModule.createBundle(identityPk, signingKey);
    return JSON.parse(res);
  }

  /**
   * Initiates a session as Alice (the sender).
   * @param {string} remoteBundleJson Serialized bundle of Bob fetched from server.
   * @param {string} localIdentityPk Base64 encoded public key of Alice.
   * @param {string} localIdentitySk Base64 encoded secret key of Alice.
   * @returns {Promise<{statePtr: number, initialMessage: object}>} Session state pointer and first message.
   */
  static async initAlice(remoteBundleJson, localIdentityPk, localIdentitySk) {
    const res = await PqAuraBridgeModule.initAlice(remoteBundleJson, localIdentityPk, localIdentitySk);
    return JSON.parse(res);
  }

  /**
   * Responds to an initiation message as Bob (the receiver).
   * @param {string} initialMsgJson Serialized Alice's InitialMessage.
   * @param {string} localIdentityPk Bob's identity public key (Base64).
   * @param {string} localIdentitySk Bob's identity secret key (Base64).
   * @param {string} localSignedSk Bob's signed pre-key secret key (Base64).
   * @param {string} localOtSk Bob's one-time pre-key secret key (Base64/optional).
   * @returns {Promise<number>} State pointer.
   */
  static async respondBob(initialMsgJson, localIdentityPk, localIdentitySk, localSignedSk, localOtSk = null) {
    return await PqAuraBridgeModule.respondBob(
      initialMsgJson,
      localIdentityPk,
      localIdentitySk,
      localSignedSk,
      localOtSk,
      !!localOtSk
    );
  }

  /**
   * Encrypts a message using a session.
   * @param {number} statePtr Pointer to native state.
   * @param {string} plaintext Base64 encoded plaintext message.
   * @param {string} ad Base64 encoded associated data.
   * @returns {Promise<{header: string, payload: string}>} Base64 encoded ciphertext elements.
   */
  static async encrypt(statePtr, plaintext, ad) {
    const res = await PqAuraBridgeModule.encrypt(statePtr, plaintext, ad);
    return JSON.parse(res);
  }

  /**
   * Decrypts a message using a session.
   * @param {number} statePtr Pointer to native state.
   * @param {string} header Base64 encoded ciphertext header.
   * @param {string} payload Base64 encoded ciphertext payload.
   * @param {string} ad Base64 encoded associated data.
   * @returns {Promise<string>} Base64 encoded decrypted plaintext.
   */
  static async decrypt(statePtr, header, payload, ad) {
    return await PqAuraBridgeModule.decrypt(statePtr, header, payload, ad);
  }

  /**
   * Safely frees state pointer memory and zeroizes secrets.
   * @param {number} statePtr Pointer to native state.
   */
  static async freeState(statePtr) {
    await PqAuraBridgeModule.freeState(statePtr);
  }
}

export default PqAuraModule;
