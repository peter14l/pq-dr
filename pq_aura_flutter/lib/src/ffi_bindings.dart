import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

// Opaque type representing the Rust RatchetState
final class RatchetState extends Opaque {}

// C structs mapped to Dart
final class FfiMessage extends Struct {
  external Pointer<Uint8> header;
  @Size()
  external int header_len;
  external Pointer<Uint8> payload;
  @Size()
  external int payload_len;
}

final class FfiKeyPair extends Struct {
  external Pointer<Uint8> public_key;
  @Size()
  external int public_key_len;
  external Pointer<Uint8> secret_key;
  @Size()
  external int secret_key_len;
}

final class FfiPreKeyBundle extends Struct {
  external Pointer<Uint8> identity_pk;
  @Size()
  external int identity_pk_len;
  external Pointer<Uint8> signed_pre_key;
  @Size()
  external int signed_pre_key_len;
  external Pointer<Uint8> one_time_pre_key;
  @Size()
  external int one_time_pre_key_len;
  @Bool()
  external bool has_one_time;
}

final class FfiInitialMessage extends Struct {
  external Pointer<RatchetState> state_ptr;
  external Pointer<Uint8> alice_identity_pk;
  @Size()
  external int alice_identity_pk_len;
  external Pointer<Uint8> ephemeral_pk;
  @Size()
  external int ephemeral_pk_len;
  external Pointer<Uint8> kem_ciphertext_identity;
  @Size()
  external int kem_ciphertext_identity_len;
  external Pointer<Uint8> kem_ciphertext_signed;
  @Size()
  external int kem_ciphertext_signed_len;
  external Pointer<Uint8> kem_ciphertext_one_time;
  @Size()
  external int kem_ciphertext_one_time_len;
  @Bool()
  external bool has_one_time;
  external Pointer<Uint8> ratchet_message_header;
  @Size()
  external int ratchet_message_header_len;
  external Pointer<Uint8> ratchet_message_payload;
  @Size()
  external int ratchet_message_payload_len;
}

class PqAuraBindings {
  late final DynamicLibrary _dylib;

  // FFI Functions
  late final Pointer<FfiKeyPair> Function() generateKeyPair;
  late final void Function(Pointer<FfiKeyPair>) freeKeyPair;
  late final Pointer<FfiPreKeyBundle> Function(Pointer<Uint8>, int) createBundle;
  late final void Function(Pointer<FfiPreKeyBundle>) freeBundle;
  
  late final Pointer<FfiInitialMessage> Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int
  ) initAlice;

  late final Pointer<RatchetState> Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<Uint8>, int, Pointer<Uint8>, int, bool
  ) initBob;

  late final Pointer<FfiMessage> Function(
    Pointer<RatchetState>, Pointer<Uint8>, int, Pointer<Uint8>, int
  ) encrypt;

  late final Pointer<Uint8> Function(
    Pointer<RatchetState>, Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<Uint8>, int, Pointer<Size>
  ) decrypt;

  late final void Function(Pointer<FfiMessage>) freeMessage;
  late final void Function(Pointer<Uint8>, int) freeBuffer;
  late final void Function(Pointer<FfiInitialMessage>) freeInitialMessage;

  late final Pointer<Uint8> Function(Pointer<RatchetState>) serializeState;
  late final int Function(Pointer<RatchetState>) serializeStateLen;
  late final Pointer<RatchetState> Function(Pointer<Uint8>, int) deserializeState;
  late final void Function(Pointer<RatchetState>) freeState;

  late final bool Function(Pointer<RatchetState>, Pointer<Utf8>, Pointer<Uint8>) saveAtomic;
  late final Pointer<RatchetState> Function(Pointer<Utf8>, Pointer<Uint8>) loadAtomic;

  PqAuraBindings() {
    _dylib = _loadLibrary();
    _initBindings();
  }

  DynamicLibrary _loadLibrary() {
    if (Platform.isAndroid) {
      return DynamicLibrary.open('libpq_aura.so');
    } else if (Platform.isIOS) {
      return DynamicLibrary.process();
    } else if (Platform.isWindows) {
      return DynamicLibrary.open('pq_aura.dll');
    } else if (Platform.isLinux) {
      return DynamicLibrary.open('libpq_aura.so');
    } else if (Platform.isMacOS) {
      return DynamicLibrary.open('libpq_aura.dylib');
    }
    throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
  }

  void _initBindings() {
    generateKeyPair = _dylib
        .lookup<NativeFunction<Pointer<FfiKeyPair> Function()>>('pqa_generate_keypair')
        .asFunction();

    freeKeyPair = _dylib
        .lookup<NativeFunction<Void Function(Pointer<FfiKeyPair>)>>('pqa_free_keypair')
        .asFunction();

    createBundle = _dylib
        .lookup<NativeFunction<Pointer<FfiPreKeyBundle> Function(Pointer<Uint8>, Size)>>('pqa_create_bundle')
        .asFunction();

    freeBundle = _dylib
        .lookup<NativeFunction<Void Function(Pointer<FfiPreKeyBundle>)>>('pqa_free_bundle')
        .asFunction();

    initAlice = _dylib
        .lookup<NativeFunction<Pointer<FfiInitialMessage> Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size)>>('pqa_init_alice')
        .asFunction();

    initBob = _dylib
        .lookup<NativeFunction<Pointer<RatchetState> Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Bool)>>('pqa_init_bob')
        .asFunction();

    encrypt = _dylib
        .lookup<NativeFunction<Pointer<FfiMessage> Function(Pointer<RatchetState>, Pointer<Uint8>, Size, Pointer<Uint8>, Size)>>('pqa_encrypt')
        .asFunction();

    decrypt = _dylib
        .lookup<NativeFunction<Pointer<Uint8> Function(Pointer<RatchetState>, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>)>>('pqa_decrypt')
        .asFunction();

    freeMessage = _dylib
        .lookup<NativeFunction<Void Function(Pointer<FfiMessage>)>>('pqa_free_message')
        .asFunction();

    freeBuffer = _dylib
        .lookup<NativeFunction<Void Function(Pointer<Uint8>, Size)>>('pqa_free_buffer')
        .asFunction();

    freeInitialMessage = _dylib
        .lookup<NativeFunction<Void Function(Pointer<FfiInitialMessage>)>>('pqa_free_initial_message')
        .asFunction();

    serializeState = _dylib
        .lookup<NativeFunction<Pointer<Uint8> Function(Pointer<RatchetState>)>>('pqa_serialize_state')
        .asFunction();

    serializeStateLen = _dylib
        .lookup<NativeFunction<Size Function(Pointer<RatchetState>)>>('pqa_serialize_state_len')
        .asFunction();

    deserializeState = _dylib
        .lookup<NativeFunction<Pointer<RatchetState> Function(Pointer<Uint8>, Size)>>('pqa_deserialize_state')
        .asFunction();

    freeState = _dylib
        .lookup<NativeFunction<Void Function(Pointer<RatchetState>)>>('pqa_free_state')
        .asFunction();

    saveAtomic = _dylib
        .lookup<NativeFunction<Bool Function(Pointer<RatchetState>, Pointer<Utf8>, Pointer<Uint8>)>>('pqa_save_atomic')
        .asFunction();

    loadAtomic = _dylib
        .lookup<NativeFunction<Pointer<RatchetState> Function(Pointer<Utf8>, Pointer<Uint8>)>>('pqa_load_atomic')
        .asFunction();
  }
}
