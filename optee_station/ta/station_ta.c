#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "station_ta.h"
#include "proto_common.h"

#define STORAGE_ID              TEE_STORAGE_PRIVATE

static const char STATION_PRIV_OBJ_ID[] = "station_x25519_priv";
static const char STATION_PUB_OBJ_ID[]  = "station_x25519_pub";
static const char PEER_PUBKEY_OBJ_ID[] = "drone_x25519_pub";
static const char SEQ_OBJ_ID[]         = "station_cmd_seq";

static TEE_ObjectHandle g_station_keypair = TEE_HANDLE_NULL;
static uint8_t g_station_pub[X25519_PUBKEY_SIZE];
static uint8_t g_station_priv[X25519_PRIVKEY_SIZE];

static uint8_t g_drone_pub[X25519_PUBKEY_SIZE];
static uint8_t shared_secret[X25519_SECRET_SIZE];
static bool g_peer_ready = false;
static bool g_station_ready = false;
static bool g_secret_ready = false;
static uint64_t g_seq = 0;

static void dump_hex(const char *label, const uint8_t *buf, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	size_t i, j;
	char line[16 * 3 + 1];

	if (!label || !buf)
		return;

	IMSG("%s:", label);
	for (i = 0; i < len; i += 16) {
		size_t chunk = (len - i > 16) ? 16 : (len - i);
		size_t pos = 0;
		for (j = 0; j < chunk; j++) {
			uint8_t b = buf[i + j];
			line[pos++] = hex[(b >> 4) & 0xF];
			line[pos++] = hex[b & 0xF];
			line[pos++] = ' ';
		}
		line[pos] = '\0';
		IMSG("%s", line);
	}
}

static void u32_to_be(uint32_t v, uint8_t out[4])
{
	out[0] = (uint8_t)((v >> 24) & 0xFF);
	out[1] = (uint8_t)((v >> 16) & 0xFF);
	out[2] = (uint8_t)((v >>  8) & 0xFF);
	out[3] = (uint8_t)(v & 0xFF);
}

static void u64_to_be(uint64_t v, uint8_t out[8])
{
	out[0] = (uint8_t)((v >> 56) & 0xFF);
	out[1] = (uint8_t)((v >> 48) & 0xFF);
	out[2] = (uint8_t)((v >> 40) & 0xFF);
	out[3] = (uint8_t)((v >> 32) & 0xFF);
	out[4] = (uint8_t)((v >> 24) & 0xFF);
	out[5] = (uint8_t)((v >> 16) & 0xFF);
	out[6] = (uint8_t)((v >>  8) & 0xFF);
	out[7] = (uint8_t)(v & 0xFF);
}

static TEE_Result read_exact_object(const char *obj_id, uint32_t obj_id_len,
                                    void *buf, uint32_t expected_len)
{
	TEE_Result res;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint32_t read_bytes = 0;

	res = TEE_OpenPersistentObject(STORAGE_ID,
	                               (void *)obj_id, obj_id_len,
	                               TEE_DATA_FLAG_ACCESS_READ,
	                               &obj);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_ReadObjectData(obj, buf, expected_len, &read_bytes);
	TEE_CloseObject(obj);

	if (res != TEE_SUCCESS)
		return res;
	if (read_bytes != expected_len)
		return TEE_ERROR_CORRUPT_OBJECT;
	return TEE_SUCCESS;
}

static TEE_Result create_object_once(const char *obj_id, uint32_t obj_id_len,
                                     const void *data, uint32_t data_len)
{
	TEE_Result res;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;

	res = TEE_CreatePersistentObject(
		STORAGE_ID,
		(void *)obj_id, obj_id_len,
		TEE_DATA_FLAG_ACCESS_READ |
		TEE_DATA_FLAG_ACCESS_WRITE |
		TEE_DATA_FLAG_ACCESS_WRITE_META,
		TEE_HANDLE_NULL,
		(void *)data, data_len,
		&obj);

	if (res == TEE_SUCCESS)
		TEE_CloseObject(obj);
	return res;
}

static TEE_Result overwrite_object(const char *obj_id, uint32_t obj_id_len,
                                   const void *data, uint32_t data_len)
{
	TEE_Result res;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;

	res = TEE_OpenPersistentObject(STORAGE_ID,
	                               (void *)obj_id, obj_id_len,
	                               TEE_DATA_FLAG_ACCESS_WRITE |
	                               TEE_DATA_FLAG_ACCESS_WRITE_META,
	                               &obj);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		return create_object_once(obj_id, obj_id_len, data, data_len);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_TruncateObjectData(obj, 0);
	if (res != TEE_SUCCESS) {
		TEE_CloseObject(obj);
		return res;
	}

	res = TEE_SeekObjectData(obj, 0, TEE_DATA_SEEK_SET);
	if (res != TEE_SUCCESS) {
		TEE_CloseObject(obj);
		return res;
	}

	res = TEE_WriteObjectData(obj, (void *)data, data_len);
	TEE_CloseObject(obj);
	return res;
}

static TEE_Result load_or_create_station_keypair(void)
{
	TEE_Result res;
	uint32_t pub_len = sizeof(g_station_pub);
	uint32_t priv_len = sizeof(g_station_priv);
	TEE_Attribute attrs[2];

	res = TEE_AllocateTransientObject(TEE_TYPE_X25519_KEYPAIR,
	                                  X25519_KEY_BITS, &g_station_keypair);
	if (res != TEE_SUCCESS)
		return res;

	res = read_exact_object(STATION_PRIV_OBJ_ID, sizeof(STATION_PRIV_OBJ_ID) - 1,
	                        g_station_priv, sizeof(g_station_priv));
	if (res == TEE_SUCCESS) {
		res = read_exact_object(STATION_PUB_OBJ_ID, sizeof(STATION_PUB_OBJ_ID) - 1,
		                        g_station_pub, sizeof(g_station_pub));
		if (res != TEE_SUCCESS)
			return res;

		TEE_InitRefAttribute(&attrs[0], TEE_ATTR_X25519_PRIVATE_VALUE,
		                     g_station_priv, sizeof(g_station_priv));
		TEE_InitRefAttribute(&attrs[1], TEE_ATTR_X25519_PUBLIC_VALUE,
		                     g_station_pub, sizeof(g_station_pub));

		res = TEE_PopulateTransientObject(g_station_keypair, attrs, 2);
		if (res != TEE_SUCCESS)
			return res;

		g_station_ready = true;
		IMSG("Station keypair loaded");
		dump_hex("Station public key", g_station_pub, sizeof(g_station_pub));
		dump_hex("Station private key", g_station_priv, sizeof(g_station_priv));
		return TEE_SUCCESS;
	}

	if (res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;

	res = TEE_GenerateKey(g_station_keypair, X25519_KEY_BITS, NULL, 0);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_GetObjectBufferAttribute(g_station_keypair,
	                                   TEE_ATTR_X25519_PUBLIC_VALUE,
	                                   g_station_pub, &pub_len);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_GetObjectBufferAttribute(g_station_keypair,
	                                   TEE_ATTR_X25519_PRIVATE_VALUE,
	                                   g_station_priv, &priv_len);
	if (res != TEE_SUCCESS)
		return res;

	res = create_object_once(STATION_PRIV_OBJ_ID, sizeof(STATION_PRIV_OBJ_ID) - 1,
	                         g_station_priv, sizeof(g_station_priv));
	if (res != TEE_SUCCESS)
		return res;

	res = create_object_once(STATION_PUB_OBJ_ID, sizeof(STATION_PUB_OBJ_ID) - 1,
	                         g_station_pub, sizeof(g_station_pub));
	if (res != TEE_SUCCESS)
		return res;

	g_station_ready = true;
	IMSG("Station keypair created");
	dump_hex("Station public key", g_station_pub, sizeof(g_station_pub));
	dump_hex("Station private key", g_station_priv, sizeof(g_station_priv));
	return TEE_SUCCESS;
}

static TEE_Result load_or_create_seq(void)
{
	TEE_Result res = read_exact_object(SEQ_OBJ_ID,
	                                   sizeof(SEQ_OBJ_ID) - 1,
	                                   &g_seq, sizeof(g_seq));
	if (res == TEE_SUCCESS) {
		IMSG("Station seq loaded: %llu", g_seq);
		return TEE_SUCCESS;
	}

	if (res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;

	g_seq = 0;
	res = create_object_once(SEQ_OBJ_ID, sizeof(SEQ_OBJ_ID) - 1,
	                         &g_seq, sizeof(g_seq));
	if (res == TEE_SUCCESS)
		IMSG("Station seq created");
	return res;
}

static TEE_Result next_seq(uint64_t *seq_out)
{
	TEE_Result res;
	g_seq++;
	res = overwrite_object(SEQ_OBJ_ID, sizeof(SEQ_OBJ_ID) - 1,
	                       &g_seq, sizeof(g_seq));
	if (res != TEE_SUCCESS)
		return res;
	*seq_out = g_seq;
	return TEE_SUCCESS;
}

static TEE_Result export_pubkey(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
	                               TEE_PARAM_TYPE_NONE,
	                               TEE_PARAM_TYPE_NONE,
	                               TEE_PARAM_TYPE_NONE);
	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size < X25519_PUBKEY_SIZE) {
		params[0].memref.size = X25519_PUBKEY_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}
	TEE_MemMove(params[0].memref.buffer, g_station_pub, X25519_PUBKEY_SIZE);
	params[0].memref.size = X25519_PUBKEY_SIZE;
	return TEE_SUCCESS;
}

static TEE_Result x25519_derive_secret(TEE_ObjectHandle my_keypair,
                                       const uint8_t peer_pub[X25519_PUBKEY_SIZE])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle secret_obj = TEE_HANDLE_NULL;
	TEE_Attribute params[1];
	uint32_t secret_len = X25519_SECRET_SIZE;

	res = TEE_AllocateOperation(&op, TEE_ALG_X25519,
	                            TEE_MODE_DERIVE, X25519_KEY_BITS);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_SetOperationKey(op, my_keypair);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
	                                  X25519_SECRET_SIZE * 8,
	                                  &secret_obj);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&params[0], TEE_ATTR_X25519_PUBLIC_VALUE,
	                     (void *)peer_pub, X25519_PUBKEY_SIZE);

	TEE_DeriveKey(op, params, 1, secret_obj);

	res = TEE_GetObjectBufferAttribute(secret_obj,
	                                   TEE_ATTR_SECRET_VALUE,
	                                   shared_secret, &secret_len);
	if (res != TEE_SUCCESS)
		goto out;

	if (secret_len != X25519_SECRET_SIZE)
		res = TEE_ERROR_BAD_STATE;
	else
		res = TEE_SUCCESS;
		
	if (res == TEE_SUCCESS) {
		g_secret_ready = true;
		IMSG("Shared secret created");
		dump_hex("Shared secret", shared_secret, sizeof(shared_secret));
	}

out:
	if (secret_obj != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(secret_obj);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	return res;
}

static TEE_Result set_peer_pubkey(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
	                               TEE_PARAM_TYPE_NONE,
	                               TEE_PARAM_TYPE_NONE,
	                               TEE_PARAM_TYPE_NONE);
	TEE_Result res;
	g_secret_ready = false;

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!params[0].memref.buffer || params[0].memref.size != X25519_PUBKEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_MemMove(g_drone_pub, params[0].memref.buffer, X25519_PUBKEY_SIZE);
	res = overwrite_object(PEER_PUBKEY_OBJ_ID,
	                       sizeof(PEER_PUBKEY_OBJ_ID) - 1,
	                       g_drone_pub, sizeof(g_drone_pub));
	if (res != TEE_SUCCESS)
		return res;

	g_peer_ready = true;
	IMSG("Drone pubkey stored");
	
	if (g_station_ready) {
	    res = x25519_derive_secret(g_station_keypair, g_drone_pub);
	    if (res != TEE_SUCCESS)
		return res;
	}
	
	return TEE_SUCCESS;
}

static TEE_Result load_peer_pubkey(void)
{
	TEE_Result res = read_exact_object(PEER_PUBKEY_OBJ_ID,
	                                   sizeof(PEER_PUBKEY_OBJ_ID) - 1,
	                                   g_drone_pub, sizeof(g_drone_pub));
	if (res == TEE_SUCCESS) {
		g_peer_ready = true;
		IMSG("Drone pubkey loaded");
		dump_hex("Drone public key", g_drone_pub, sizeof(g_drone_pub));
		res = x25519_derive_secret(g_station_keypair, g_drone_pub);
		if (res != TEE_SUCCESS)
			IMSG("Shared secret not set yet");
	}
	return res;
}

static TEE_Result hkdf_derive_aes_key(const uint8_t shared_secret[X25519_SECRET_SIZE],
                                      uint64_t seq,
                                      const uint8_t nonce[GCM_NONCE_SIZE],
                                      uint8_t out_key[AES_KEY_SIZE])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle ikm_obj = TEE_HANDLE_NULL;
	TEE_ObjectHandle derived_obj = TEE_HANDLE_NULL;
	TEE_Attribute ikm_attr;
	TEE_Attribute params[3];

	static const uint8_t salt[] = "GS-UAV-X25519-SALT";
	static const uint8_t info_prefix[] = "GS2UAV-CMD-V1";
	uint8_t info[(sizeof(info_prefix) - 1) + 8 + GCM_NONCE_SIZE];
	uint32_t out_len = AES_KEY_SIZE;
	uint8_t seq_be[8];

	u64_to_be(seq, seq_be);
	TEE_MemMove(info, info_prefix, sizeof(info_prefix) - 1);
	TEE_MemMove(info + sizeof(info_prefix) - 1, seq_be, 8);
	TEE_MemMove(info + sizeof(info_prefix) - 1 + 8, nonce, GCM_NONCE_SIZE);

	res = TEE_AllocateOperation(&op, TEE_ALG_HKDF_SHA256_DERIVE_KEY,
	                            TEE_MODE_DERIVE, X25519_SECRET_SIZE * 8);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateTransientObject(TEE_TYPE_HKDF_IKM,
	                                  X25519_SECRET_SIZE * 8,
	                                  &ikm_obj);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&ikm_attr, TEE_ATTR_HKDF_IKM,
	                     (void *)shared_secret, X25519_SECRET_SIZE);
	res = TEE_PopulateTransientObject(ikm_obj, &ikm_attr, 1);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_SetOperationKey(op, ikm_obj);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
	                                  AES_KEY_SIZE * 8, &derived_obj);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&params[0], TEE_ATTR_HKDF_SALT,
	                     (void *)salt, sizeof(salt) - 1);
	TEE_InitRefAttribute(&params[1], TEE_ATTR_HKDF_INFO,
	                     (void *)info, sizeof(info));
	TEE_InitValueAttribute(&params[2], TEE_ATTR_HKDF_OKM_LENGTH,
	                       AES_KEY_SIZE, 0);

	TEE_DeriveKey(op, params, 3, derived_obj);

	res = TEE_GetObjectBufferAttribute(derived_obj, TEE_ATTR_SECRET_VALUE,
	                                   out_key, &out_len);
	if (res != TEE_SUCCESS)
		goto out;

	if (out_len != AES_KEY_SIZE)
		res = TEE_ERROR_BAD_STATE;
	else
		res = TEE_SUCCESS;

out:
	if (derived_obj != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(derived_obj);
	if (ikm_obj != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(ikm_obj);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	return res;
}

static TEE_Result aes_gcm_encrypt(const uint8_t key[AES_KEY_SIZE],
                                  const uint8_t nonce[GCM_NONCE_SIZE],
                                  const uint8_t *aad, uint32_t aad_len,
                                  const uint8_t *pt, uint32_t pt_len,
                                  uint8_t *ct, uint32_t *ct_len,
                                  uint8_t tag[GCM_TAG_SIZE], uint32_t *tag_len)
{
	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
	TEE_Attribute attr;

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM,
	                            TEE_MODE_ENCRYPT, AES_KEY_SIZE * 8);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateTransientObject(TEE_TYPE_AES,
	                                  AES_KEY_SIZE * 8, &key_obj);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
	                     (void *)key, AES_KEY_SIZE);
	res = TEE_PopulateTransientObject(key_obj, &attr, 1);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_SetOperationKey(op, key_obj);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_AEInit(op, (void *)nonce, GCM_NONCE_SIZE, GCM_TAG_SIZE * 8, 0, 0);

	if (aad && aad_len > 0)
		TEE_AEUpdateAAD(op, (void *)aad, aad_len);

	res = TEE_AEEncryptFinal(op, (void *)pt, pt_len,
	                         ct, ct_len, tag, tag_len);

out:
	if (key_obj != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_obj);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	return res;
}

static TEE_Result encrypt_command(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
	                               TEE_PARAM_TYPE_MEMREF_OUTPUT,
	                               TEE_PARAM_TYPE_VALUE_OUTPUT,
	                               TEE_PARAM_TYPE_NONE);
	TEE_Result res;
	uint8_t session_key[AES_KEY_SIZE];
	uint8_t nonce[GCM_NONCE_SIZE];
	uint8_t tag[GCM_TAG_SIZE];
	uint8_t aad[1 + 1 + 8 + GCM_NONCE_SIZE + 4];
	uint8_t seq_be[8];
	uint8_t ct_len_be[4];
	uint8_t *out;
	uint8_t *ciphertext_ptr;
	uint8_t *tag_ptr;
	uint32_t pt_len;
	uint32_t ct_len;
	uint32_t tag_len = GCM_TAG_SIZE;
	uint32_t needed;
	uint64_t seq = 0;
	uint8_t msg_type = MSG_TYPE_GS_COMMAND;

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!g_station_ready || !g_peer_ready)
		return TEE_ERROR_BAD_STATE;
	if (!params[0].memref.buffer || !params[1].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;
		
	if (!g_secret_ready)
		return TEE_ERROR_BAD_STATE;

	pt_len = params[0].memref.size;
	needed = 1 + 1 + 8 + GCM_NONCE_SIZE + 4 + pt_len + GCM_TAG_SIZE;
	if (params[1].memref.size < needed) {
		params[1].memref.size = needed;
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = next_seq(&seq);
	if (res != TEE_SUCCESS)
		return res;

	TEE_GenerateRandom(nonce, GCM_NONCE_SIZE);

	res = hkdf_derive_aes_key(shared_secret, seq, nonce, session_key);
	if (res != TEE_SUCCESS)
		goto out;

	u64_to_be(seq, seq_be);
	u32_to_be(pt_len, ct_len_be);

	aad[0] = RECORD_VERSION;
	aad[1] = msg_type;
	TEE_MemMove(&aad[2], seq_be, 8);
	TEE_MemMove(&aad[10], nonce, GCM_NONCE_SIZE);
	TEE_MemMove(&aad[22], ct_len_be, 4);

	out = (uint8_t *)params[1].memref.buffer;
	ciphertext_ptr = out + 1 + 1 + 8 + GCM_NONCE_SIZE + 4;
	tag_ptr = ciphertext_ptr + pt_len;
	ct_len = pt_len;

	res = aes_gcm_encrypt(session_key, nonce, aad, sizeof(aad),
	                      params[0].memref.buffer, pt_len,
	                      ciphertext_ptr, &ct_len,
	                      tag, &tag_len);
	if (res != TEE_SUCCESS)
		goto out;

	out[0] = RECORD_VERSION;
	out[1] = msg_type;
	TEE_MemMove(out + 2, seq_be, 8);
	TEE_MemMove(out + 10, nonce, GCM_NONCE_SIZE);
	TEE_MemMove(out + 22, ct_len_be, 4);
	TEE_MemMove(tag_ptr, tag, GCM_TAG_SIZE);

	params[1].memref.size = 1 + 1 + 8 + GCM_NONCE_SIZE + 4 + ct_len + tag_len;
	params[2].value.a = (uint32_t)(seq & 0xffffffffu);
	params[2].value.b = (uint32_t)((seq >> 32) & 0xffffffffu);
	
	IMSG("message_type = 0x%x", msg_type);
	IMSG("seq = %llu", seq);
	dump_hex("Derived key", session_key, sizeof(session_key));
	dump_hex("Nonce", nonce, sizeof(nonce));
	dump_hex("Ciphertext", ciphertext_ptr, ct_len);
	dump_hex("Tag", tag, sizeof(tag));
	dump_hex("Full packet", out, params[1].memref.size);

out:
	TEE_MemFill(session_key, 0, sizeof(session_key));
	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	TEE_Result res;

	res = load_or_create_station_keypair();
	if (res != TEE_SUCCESS)
		return res;

	res = load_peer_pubkey();
	if (res != TEE_SUCCESS)
		IMSG("Drone pubkey not set yet");

	res = load_or_create_seq();
	if (res != TEE_SUCCESS)
		return res;

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	if (g_station_keypair != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(g_station_keypair);
	TEE_MemFill(shared_secret, 0, sizeof(shared_secret));
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx)
{
	(void)params;
	(void)sess_ctx;
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
	                               TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	return (param_types == exp) ? TEE_SUCCESS : TEE_ERROR_BAD_PARAMETERS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)sess_ctx;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4])
{
	(void)sess_ctx;
	switch (cmd_id) {
	case TA_STATION_CMD_EXPORT_PUBKEY:
		return export_pubkey(param_types, params);
	case TA_STATION_CMD_SET_PEER_PUBKEY:
		return set_peer_pubkey(param_types, params);
	case TA_STATION_CMD_ENCRYPT_COMMAND:
		return encrypt_command(param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
