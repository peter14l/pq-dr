import 'dart:convert';
import 'dart:typed_data';

class PqKeyPair {
  final Uint8List publicKey;
  final Uint8List secretKey;

  PqKeyPair({required this.publicKey, required this.secretKey});
}

class PqPreKeyBundle {
  final Uint8List identityPk;
  final Uint8List signedPreKey;
  final Uint8List? oneTimePreKey;

  PqPreKeyBundle({
    required this.identityPk,
    required this.signedPreKey,
    this.oneTimePreKey,
  });

  Map<String, dynamic> toJson() {
    return {
      'identity_pk': base64Encode(identityPk),
      'signed_pre_key': base64Encode(signedPreKey),
      'one_time_pre_key': oneTimePreKey != null ? base64Encode(oneTimePreKey!) : null,
    };
  }

  factory PqPreKeyBundle.fromJson(Map<String, dynamic> json) {
    return PqPreKeyBundle(
      identityPk: base64Decode(json['identity_pk']),
      signedPreKey: base64Decode(json['signed_pre_key']),
      oneTimePreKey: json['one_time_pre_key'] != null ? base64Decode(json['one_time_pre_key']) : null,
    );
  }
}

class PqMessage {
  final Uint8List header;
  final Uint8List payload;

  PqMessage({required this.header, required this.payload});

  Map<String, dynamic> toJson() {
    return {
      'header': base64Encode(header),
      'payload': base64Encode(payload),
    };
  }

  factory PqMessage.fromJson(Map<String, dynamic> json) {
    return PqMessage(
      header: base64Decode(json['header']),
      payload: base64Decode(json['payload']),
    );
  }
}

class PqInitialMessage {
  final Uint8List aliceIdentityPk;
  final Uint8List ephemeralPk;
  final Uint8List kemCiphertextIdentity;
  final Uint8List kemCiphertextSigned;
  final Uint8List? kemCiphertextOneTime;
  final PqMessage ratchetMessage;

  PqInitialMessage({
    required this.aliceIdentityPk,
    required this.ephemeralPk,
    required this.kemCiphertextIdentity,
    required this.kemCiphertextSigned,
    this.kemCiphertextOneTime,
    required this.ratchetMessage,
  });

  Map<String, dynamic> toJson() {
    return {
      'alice_identity_pk': base64Encode(aliceIdentityPk),
      'ephemeral_pk': base64Encode(ephemeralPk),
      'kem_ciphertext_identity': base64Encode(kemCiphertextIdentity),
      'kem_ciphertext_signed': base64Encode(kemCiphertextSigned),
      'kem_ciphertext_one_time': kemCiphertextOneTime != null ? base64Encode(kemCiphertextOneTime!) : null,
      'ratchet_message': ratchetMessage.toJson(),
    };
  }

  factory PqInitialMessage.fromJson(Map<String, dynamic> json) {
    return PqInitialMessage(
      aliceIdentityPk: base64Decode(json['alice_identity_pk']),
      ephemeralPk: base64Decode(json['ephemeral_pk']),
      kemCiphertextIdentity: base64Decode(json['kem_ciphertext_identity']),
      kemCiphertextSigned: base64Decode(json['kem_ciphertext_signed']),
      kemCiphertextOneTime: json['kem_ciphertext_one_time'] != null ? base64Decode(json['kem_ciphertext_one_time']) : null,
      ratchetMessage: PqMessage.fromJson(json['ratchet_message']),
    );
  }
}
