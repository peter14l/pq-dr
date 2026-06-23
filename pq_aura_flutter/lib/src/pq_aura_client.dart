import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'ffi_bindings.dart' as ffi;
import 'pq_aura_types.dart';

class PqAuraClient {
  static final ffi.PqAuraBindings _bindings = ffi.PqAuraBindings();

  /// Generates a new hybrid keypair (X25519 + ML-KEM-1024).
  static PqKeyPair generateKeyPair() {
    final kpPtr = _bindings.generateKeyPair();
    try {
      final kp = kpPtr.ref;
      final pubKey = _toDart(kp.public_key, kp.public_key_len);
      final secKey = _toDart(kp.secret_key, kp.secret_key_len);
      return PqKeyPair(publicKey: pubKey, secretKey: secKey);
    } finally {
      _bindings.freeKeyPair(kpPtr);
    }
  }

  /// Creates a PreKeyBundle from an identity public key.
  static PqPreKeyBundle createBundle(Uint8List identityPk) {
    final identityPkPtr = _toNative(identityPk);
    final bundlePtr = _bindings.createBundle(identityPkPtr, identityPk.length);
    try {
      if (bundlePtr == nullptr) {
        throw Exception('Failed to create pre-key bundle');
      }
      final bundle = bundlePtr.ref;
      return PqPreKeyBundle(
        identityPk: _toDart(bundle.identity_pk, bundle.identity_pk_len),
        signedPreKey: _toDart(bundle.signed_pre_key, bundle.signed_pre_key_len),
        oneTimePreKey: bundle.has_one_time 
            ? _toDart(bundle.one_time_pre_key, bundle.one_time_pre_key_len) 
            : null,
      );
    } finally {
      malloc.free(identityPkPtr);
      _bindings.freeBundle(bundlePtr);
    }
  }

  /// Initiates a session as Alice (initiator).
  static AliceHandshakeResult initAlice({
    required PqPreKeyBundle remoteBundle,
    required PqKeyPair localIdentityKeyPair,
  }) {
    final bundleJson = remoteBundle.toJson();
    final bundleBytes = Uint8List.fromList(utf8.encode(jsonEncode(bundleJson)));
    final bundlePtr = _toNative(bundleBytes);

    final localPkPtr = _toNative(localIdentityKeyPair.publicKey);
    final localSkPtr = _toNative(localIdentityKeyPair.secretKey);

    final initMsgPtr = _bindings.initAlice(
      bundlePtr,
      bundleBytes.length,
      localPkPtr,
      localIdentityKeyPair.publicKey.length,
      localSkPtr,
      localIdentityKeyPair.secretKey.length,
    );

    try {
      if (initMsgPtr == nullptr) {
        throw Exception('Failed to initiate Alice session');
      }
      final initMsg = initMsgPtr.ref;

      final session = PqSession._(initMsg.state_ptr);
      final initialMessage = PqInitialMessage(
        aliceIdentityPk: _toDart(initMsg.alice_identity_pk, initMsg.alice_identity_pk_len),
        ephemeralPk: _toDart(initMsg.ephemeral_pk, initMsg.ephemeral_pk_len),
        kemCiphertextIdentity: _toDart(initMsg.kem_ciphertext_identity, initMsg.kem_ciphertext_identity_len),
        kemCiphertextSigned: _toDart(initMsg.kem_ciphertext_signed, initMsg.kem_ciphertext_signed_len),
        kemCiphertextOneTime: initMsg.has_one_time
            ? _toDart(initMsg.kem_ciphertext_one_time, initMsg.kem_ciphertext_one_time_len)
            : null,
        ratchetMessage: PqMessage(
          header: _toDart(initMsg.ratchet_message_header, initMsg.ratchet_message_header_len),
          payload: _toDart(initMsg.ratchet_message_payload, initMsg.ratchet_message_payload_len),
        ),
      );

      return AliceHandshakeResult(session: session, initialMessage: initialMessage);
    } finally {
      malloc.free(bundlePtr);
      malloc.free(localPkPtr);
      malloc.free(localSkPtr);
      _bindings.freeInitialMessage(initMsgPtr);
    }
  }

  /// Responds to an initial message as Bob (receiver).
  static PqSession initBob({
    required PqInitialMessage initialMsg,
    required PqKeyPair localIdentityKeyPair,
    required PqKeyPair localSignedKeyPair,
    PqKeyPair? localOneTimeKeyPair,
  }) {
    final msgJson = initialMsg.toJson();
    final msgBytes = Uint8List.fromList(utf8.encode(jsonEncode(msgJson)));
    final msgPtr = _toNative(msgBytes);

    final localIdPkPtr = _toNative(localIdentityKeyPair.publicKey);
    final localIdSkPtr = _toNative(localIdentityKeyPair.secretKey);
    final localSignedSkPtr = _toNative(localSignedKeyPair.secretKey);

    Pointer<Uint8> localOtSkPtr = nullptr;
    int localOtSkLen = 0;
    if (localOneTimeKeyPair != null) {
      localOtSkPtr = _toNative(localOneTimeKeyPair.secretKey);
      localOtSkLen = localOneTimeKeyPair.secretKey.length;
    }

    final statePtr = _bindings.initBob(
      msgPtr,
      msgBytes.length,
      localIdPkPtr,
      localIdentityKeyPair.publicKey.length,
      localIdSkPtr,
      localIdentityKeyPair.secretKey.length,
      localSignedSkPtr,
      localSignedKeyPair.secretKey.length,
      localOtSkPtr,
      localOtSkLen,
      localOneTimeKeyPair != null,
    );

    try {
      if (statePtr == nullptr) {
        throw Exception('Failed to initialize Bob session');
      }
      return PqSession._(statePtr);
    } finally {
      malloc.free(msgPtr);
      malloc.free(localIdPkPtr);
      malloc.free(localIdSkPtr);
      malloc.free(localSignedSkPtr);
      if (localOtSkPtr != nullptr) {
        malloc.free(localOtSkPtr);
      }
    }
  }
}

class AliceHandshakeResult {
  final PqSession session;
  final PqInitialMessage initialMessage;

  AliceHandshakeResult({required this.session, required this.initialMessage});
}

class PqSession {
  Pointer<ffi.RatchetState> _statePtr;

  PqSession._(this._statePtr);

  /// Encrypts a message.
  PqMessage encrypt(Uint8List plaintext, Uint8List ad) {
    final plaintextPtr = _toNative(plaintext);
    final adPtr = _toNative(ad);

    final msgPtr = PqAuraClient._bindings.encrypt(
      _statePtr,
      plaintextPtr,
      plaintext.length,
      adPtr,
      ad.length,
    );

    try {
      if (msgPtr == nullptr) {
        throw Exception('Encryption failed');
      }
      final msg = msgPtr.ref;
      return PqMessage(
        header: _toDart(msg.header, msg.header_len),
        payload: _toDart(msg.payload, msg.payload_len),
      );
    } finally {
      malloc.free(plaintextPtr);
      malloc.free(adPtr);
      PqAuraClient._bindings.freeMessage(msgPtr);
    }
  }

  /// Decrypts a message.
  Uint8List decrypt(PqMessage message, Uint8List ad) {
    final headerPtr = _toNative(message.header);
    final payloadPtr = _toNative(message.payload);
    final adPtr = _toNative(ad);
    final outLenPtr = malloc<Size>();

    final decryptedPtr = PqAuraClient._bindings.decrypt(
      _statePtr,
      headerPtr,
      message.header.length,
      payloadPtr,
      message.payload.length,
      adPtr,
      ad.length,
      outLenPtr,
    );

    try {
      if (decryptedPtr == nullptr) {
        throw Exception('Decryption failed');
      }
      final outLen = outLenPtr.value;
      return _toDart(decryptedPtr, outLen);
    } finally {
      malloc.free(headerPtr);
      malloc.free(payloadPtr);
      malloc.free(adPtr);
      malloc.free(outLenPtr);
      if (decryptedPtr != nullptr) {
        PqAuraClient._bindings.freeBuffer(decryptedPtr, outLenPtr.value);
      }
    }
  }

  /// Serializes the session state.
  Uint8List serializeState() {
    final len = PqAuraClient._bindings.serializeStateLen(_statePtr);
    if (len == 0) {
      throw Exception('Failed to get serialized state length');
    }
    final bytesPtr = PqAuraClient._bindings.serializeState(_statePtr);
    try {
      if (bytesPtr == nullptr) {
        throw Exception('Failed to serialize state');
      }
      return _toDart(bytesPtr, len);
    } finally {
      if (bytesPtr != nullptr) {
        PqAuraClient._bindings.freeBuffer(bytesPtr, len);
      }
    }
  }

  /// Deserializes a session state.
  static PqSession deserializeState(Uint8List stateBytes) {
    final bytesPtr = _toNative(stateBytes);
    final statePtr = PqAuraClient._bindings.deserializeState(bytesPtr, stateBytes.length);
    try {
      if (statePtr == nullptr) {
        throw Exception('Failed to deserialize state');
      }
      return PqSession._(statePtr);
    } finally {
      malloc.free(bytesPtr);
    }
  }

  /// Atomically saves the state to disk.
  bool saveAtomic(String path, Uint8List encryptionKey) {
    if (encryptionKey.length != 32) {
      throw ArgumentError('Encryption key must be exactly 32 bytes');
    }
    final pathPtr = path.toNativeUtf8();
    final keyPtr = _toNative(encryptionKey);
    try {
      return PqAuraClient._bindings.saveAtomic(_statePtr, pathPtr, keyPtr);
    } finally {
      malloc.free(pathPtr);
      malloc.free(keyPtr);
    }
  }

  /// Loads the state from disk.
  static PqSession loadAtomic(String path, Uint8List encryptionKey) {
    if (encryptionKey.length != 32) {
      throw ArgumentError('Encryption key must be exactly 32 bytes');
    }
    final pathPtr = path.toNativeUtf8();
    final keyPtr = _toNative(encryptionKey);
    try {
      final statePtr = PqAuraClient._bindings.loadAtomic(pathPtr, keyPtr);
      if (statePtr == nullptr) {
        throw Exception('Failed to load state atomically from path: $path');
      }
      return PqSession._(statePtr);
    } finally {
      malloc.free(pathPtr);
      malloc.free(keyPtr);
    }
  }

  /// Frees the state from native memory.
  void free() {
    if (_statePtr != nullptr) {
      PqAuraClient._bindings.freeState(_statePtr);
      _statePtr = nullptr;
    }
  }
}

// Helpers for memory allocation
Pointer<Uint8> _toNative(Uint8List list) {
  final ptr = malloc<Uint8>(list.length);
  final view = ptr.asTypedList(list.length);
  view.setAll(0, list);
  return ptr;
}

Uint8List _toDart(Pointer<Uint8> ptr, int length) {
  final view = ptr.asTypedList(length);
  return Uint8List.fromList(view);
}

// Simple JSON encoder/decoder helper
dynamic jsonEncode(dynamic value) {
  return json.encode(value);
}

dynamic jsonDecode(String value) {
  return json.decode(value);
}

const json = JsonCodec();
