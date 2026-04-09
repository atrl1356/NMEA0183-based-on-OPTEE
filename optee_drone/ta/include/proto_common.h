#ifndef PROTO_COMMON_H
#define PROTO_COMMON_H

#define RECORD_VERSION          0x01
#define MSG_TYPE_GS_COMMAND     0x01
#define MSG_TYPE_UAV_LOG        0x02

#define X25519_KEY_BITS         256
#define X25519_PUBKEY_SIZE      32
#define X25519_PRIVKEY_SIZE     32
#define X25519_SECRET_SIZE      32

#define AES_KEY_SIZE            32
#define GCM_NONCE_SIZE          12
#define GCM_TAG_SIZE            16

#endif
