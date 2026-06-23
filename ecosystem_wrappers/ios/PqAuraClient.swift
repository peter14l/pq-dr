import Foundation

/// Swift client wrapper for the PQ-Aura Hybrid Post-Quantum Double Ratchet.
/// Manages the underlying raw memory pointers and zeroization drop logic cleanly.
public class PqAuraClient {
    private var statePtr: OpaquePointer?

    /// Initializes a session as Alice (the initiator).
    public init(remoteBundleJson: String, localIdentityPk: Data, localIdentitySk: Data) throws {
        let remoteBundleBytes = Array(remoteBundleJson.utf8)
        let alicePkBytes = Array(localIdentityPk)
        let aliceSkBytes = Array(localIdentitySk)

        let initialMessagePtr = pqa_init_alice(
            remoteBundleBytes, remoteBundleBytes.count,
            alicePkBytes, alicePkBytes.count,
            aliceSkBytes, aliceSkBytes.count
        )

        guard let initialMsg = initialMessagePtr else {
            throw PqAuraError.handshakeFailed
        }

        self.statePtr = initialMsg.pointee.state_ptr
        pqa_free_initial_message(initialMessagePtr)
    }

    /// Initializes a session as Bob (the receiver).
    public init(initialMsgJson: String, localIdentityPk: Data, localIdentitySk: Data, localSignedSk: Data, localOtSk: Data?) throws {
        let msgBytes = Array(initialMsgJson.utf8)
        let bobPkBytes = Array(localIdentityPk)
        let bobSkBytes = Array(localIdentitySk)
        let signedSkBytes = Array(localSignedSk)

        let state: OpaquePointer?
        if let otSk = localOtSk {
            let otSkBytes = Array(otSk)
            state = pqa_init_bob(
                msgBytes, msgBytes.count,
                bobPkBytes, bobPkBytes.count,
                bobSkBytes, bobSkBytes.count,
                signedSkBytes, signedSkBytes.count,
                otSkBytes, otSkBytes.count,
                true
            )
        } else {
            state = pqa_init_bob(
                msgBytes, msgBytes.count,
                bobPkBytes, bobPkBytes.count,
                bobSkBytes, bobSkBytes.count,
                signedSkBytes, signedSkBytes.count,
                nil, 0,
                false
            )
        }

        guard let validState = state else {
            throw PqAuraError.handshakeFailed
        }
        self.statePtr = validState
    }

    /// Encrypts a message.
    public func encrypt(plaintext: Data, ad: Data) throws -> (header: Data, payload: Data) {
        guard let state = statePtr else { throw PqAuraError.sessionClosed }

        let plainBytes = Array(plaintext)
        let adBytes = Array(ad)

        guard let ffiMsg = pqa_encrypt(state, plainBytes, plainBytes.count, adBytes, adBytes.count) else {
            throw PqAuraError.encryptionFailed
        }

        let headerData = Data(bytes: ffiMsg.pointee.header, count: ffiMsg.pointee.header_len)
        let payloadData = Data(bytes: ffiMsg.pointee.payload, count: ffiMsg.pointee.payload_len)

        pqa_free_message(ffiMsg)
        return (headerData, payloadData)
    }

    /// Decrypts a message.
    public func decrypt(header: Data, payload: Data, ad: Data) throws -> Data {
        guard let state = statePtr else { throw PqAuraError.sessionClosed }

        let headerBytes = Array(header)
        let payloadBytes = Array(payload)
        let adBytes = Array(ad)
        var outLen: Int = 0

        guard let plainPtr = pqa_decrypt(
            state,
            headerBytes, headerBytes.count,
            payloadBytes, payloadBytes.count,
            adBytes, adBytes.count,
            &outLen
        ) else {
            throw PqAuraError.decryptionFailed
        }

        let plaintext = Data(bytes: plainPtr, count: outLen)
        pqa_free_buffer(plainPtr, outLen)
        return plaintext
    }

    /// Persists session state atomically with AES encryption.
    public func saveAtomic(path: String, key: Data) -> Bool {
        guard let state = statePtr else { return false }
        let keyBytes = Array(key)
        return pqa_save_atomic(state, path, keyBytes)
    }

    /// Loads session state atomically with AES encryption.
    public static func loadAtomic(path: String, key: Data) throws -> PqAuraClient {
        let keyBytes = Array(key)
        guard let state = pqa_load_atomic(path, keyBytes) else {
            throw PqAuraError.loadFailed
        }
        let client = PqAuraClient()
        client.statePtr = state
        return client
    }

    private init() {}

    deinit {
        if let state = statePtr {
            pqa_free_state(state)
        }
    }
}

public enum PqAuraError: Error {
    case handshakeFailed
    case encryptionFailed
    case decryptionFailed
    case sessionClosed
    case loadFailed
}
