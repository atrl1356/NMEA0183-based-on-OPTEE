#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "drone_ta.h"
#include "proto_common.h"

#define STORAGE_ID              TEE_STORAGE_PRIVATE

static const char UAV_PRIV_OBJ_ID[] = "uav_x25519_priv";
static const char UAV_PUB_OBJ_ID[]  = "uav_x25519_pub";
static const char PEER_PUBKEY_OBJ_ID[] = "station_x25519_pub";

static TEE_ObjectHandle g_uav_keypair = TEE_HANDLE_NULL;
static uint8_t g_uav_pub[X25519_PUBKEY_SIZE];
static uint8_t g_uav_priv[X25519_PRIVKEY_SIZE];
static uint8_t g_station_pub[X25519_PUBKEY_SIZE];
static uint8_t shared_secret[X25519_SECRET_SIZE];
static bool g_uav_ready = false;
static bool g_peer_ready = false;
static bool g_secret_ready = false;

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

static uint32_t be32_to_u32(const uint8_t in[4])
{
	return ((uint32_t)in[0] << 24) |
	       ((uint32_t)in[1] << 16) |
	       ((uint32_t)in[2] << 8) |
	       (uint32_t)in[3];
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

static uint64_t be64_to_u64(const uint8_t in[8])
{
	return ((uint64_t)in[0] << 56) |
	       ((uint64_t)in[1] << 48) |
	       ((uint64_t)in[2] << 40) |
	       ((uint64_t)in[3] << 32) |
	       ((uint64_t)in[4] << 24) |
	       ((uint64_t)in[5] << 16) |
	       ((uint64_t)in[6] << 8) |
	       (uint64_t)in[7];
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

static TEE_Result load_or_create_uav_keypair(void)
{
	TEE_Result res;
	uint32_t pub_len = sizeof(g_uav_pub);
	uint32_t priv_len = sizeof(g_uav_priv);
	TEE_Attribute attrs[2];

	res = TEE_AllocateTransientObject(TEE_TYPE_X25519_KEYPAIR,
	                                  X25519_KEY_BITS, &g_uav_keypair);
	if (res != TEE_SUCCESS)
		return res;

	res = read_exact_object(UAV_PRIV_OBJ_ID, sizeof(UAV_PRIV_OBJ_ID) - 1,
	                        g_uav_priv, sizeof(g_uav_priv));
	if (res == TEE_SUCCESS) {
		res = read_exact_object(UAV_PUB_OBJ_ID, sizeof(UAV_PUB_OBJ_ID) - 1,
		                        g_uav_pub, sizeof(g_uav_pub));
		if (res != TEE_SUCCESS)
			return res;

		TEE_InitRefAttribute(&attrs[0], TEE_ATTR_X25519_PRIVATE_VALUE,
		                     g_uav_priv, sizeof(g_uav_priv));
		TEE_InitRefAttribute(&attrs[1], TEE_ATTR_X25519_PUBLIC_VALUE,
		                     g_uav_pub, sizeof(g_uav_pub));

		res = TEE_PopulateTransientObject(g_uav_keypair, attrs, 2);
		if (res != TEE_SUCCESS)
			return res;

		g_uav_ready = true;
		IMSG("Drone keypair loaded");
		dump_hex("Drone public key", g_uav_pub, sizeof(g_uav_pub));
		dump_hex("Drone private key", g_uav_priv, sizeof(g_uav_priv));
		return TEE_SUCCESS;
	}

	if (res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;

	res = TEE_GenerateKey(g_uav_keypair, X25519_KEY_BITS, NULL, 0);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_GetObjectBufferAttribute(g_uav_keypair,
	                                   TEE_ATTR_X25519_PUBLIC_VALUE,
	                                   g_uav_pub, &pub_len);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_GetObjectBufferAttribute(g_uav_keypair,
	                                   TEE_ATTR_X25519_PRIVATE_VALUE,
	                                   g_uav_priv, &priv_len);
	if (res != TEE_SUCCESS)
		return res;

	res = create_object_once(UAV_PRIV_OBJ_ID, sizeof(UAV_PRIV_OBJ_ID) - 1,
	                         g_uav_priv, sizeof(g_uav_priv));
	if (res != TEE_SUCCESS)
		return res;

	res = create_object_once(UAV_PUB_OBJ_ID, sizeof(UAV_PUB_OBJ_ID) - 1,
	                         g_uav_pub, sizeof(g_uav_pub));
	if (res != TEE_SUCCESS)
		return res;

	g_uav_ready = true;
	IMSG("Drone keypair created");
	dump_hex("Drone public key", g_uav_pub, sizeof(g_uav_pub));
	dump_hex("Drone private key", g_uav_priv, sizeof(g_uav_priv));
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

	TEE_MemMove(params[0].memref.buffer, g_uav_pub, X25519_PUBKEY_SIZE);
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

	TEE_MemMove(g_station_pub, params[0].memref.buffer, X25519_PUBKEY_SIZE);
	res = overwrite_object(PEER_PUBKEY_OBJ_ID,
	                       sizeof(PEER_PUBKEY_OBJ_ID) - 1,
	                       g_station_pub, sizeof(g_station_pub));
	if (res != TEE_SUCCESS)
		return res;

	g_peer_ready = true;
	IMSG("Station pubkey stored");
	
	if (g_uav_ready) {
	    res = x25519_derive_secret(g_uav_keypair, g_station_pub);
	    if (res != TEE_SUCCESS)
		return res;
	}
	
	return TEE_SUCCESS;
}

static TEE_Result load_peer_pubkey(void)
{
	TEE_Result res = read_exact_object(PEER_PUBKEY_OBJ_ID,
	                                   sizeof(PEER_PUBKEY_OBJ_ID) - 1,
	                                   g_station_pub, sizeof(g_station_pub));
	if (res == TEE_SUCCESS) {
		g_peer_ready = true;
		IMSG("Station pubkey loaded");
		dump_hex("Station public key", g_station_pub, sizeof(g_station_pub));
		res = x25519_derive_secret(g_uav_keypair, g_station_pub);
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
	uint8_t seq_be[8];
	uint32_t out_len = AES_KEY_SIZE;

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

static TEE_Result aes_gcm_decrypt(const uint8_t key[AES_KEY_SIZE],
                                  const uint8_t nonce[GCM_NONCE_SIZE],
                                  const uint8_t *aad, uint32_t aad_len,
                                  const uint8_t *ct, uint32_t ct_len,
                                  const uint8_t tag[GCM_TAG_SIZE],
                                  uint8_t *pt, uint32_t *pt_len)
{
	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
	TEE_Attribute attr;

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM,
	                            TEE_MODE_DECRYPT, AES_KEY_SIZE * 8);
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

	res = TEE_AEDecryptFinal(op, (void *)ct, ct_len,
	                         pt, pt_len,
	                         (void *)tag, GCM_TAG_SIZE);

out:
	if (key_obj != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_obj);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	return res;
}

static TEE_Result decrypt_packet(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
	                               TEE_PARAM_TYPE_MEMREF_OUTPUT,
	                               TEE_PARAM_TYPE_VALUE_OUTPUT,
	                               TEE_PARAM_TYPE_NONE);
	const uint8_t *in;
	uint32_t in_len;
	const uint8_t *nonce;
	const uint8_t *ct;
	const uint8_t *tag;
	uint8_t msg_type;
	uint64_t seq;
	uint32_t ct_len;
	uint8_t session_key[AES_KEY_SIZE];
	uint8_t aad[1 + 1 + 8 + GCM_NONCE_SIZE + 4];
	uint8_t ct_len_be[4];
	uint32_t pt_len;
	TEE_Result res;

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!g_uav_ready || !g_peer_ready)
		return TEE_ERROR_BAD_STATE;
	if (!params[0].memref.buffer || !params[1].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;
		
	if (!g_secret_ready)
		return TEE_ERROR_BAD_STATE;

	in = (const uint8_t *)params[0].memref.buffer;
	in_len = params[0].memref.size;

	if (in_len < 1 + 1 + 8 + GCM_NONCE_SIZE + 4 + GCM_TAG_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
	if (in[0] != RECORD_VERSION)
		return TEE_ERROR_BAD_PARAMETERS;

	msg_type = in[1];
	seq = be64_to_u64(in + 2);
	nonce = in + 10;
	ct_len = be32_to_u32(in + 22);

	if (in_len != 1 + 1 + 8 + GCM_NONCE_SIZE + 4 + ct_len + GCM_TAG_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	ct = in + 26;
	tag = ct + ct_len;

	if (params[1].memref.size < ct_len) {
		params[1].memref.size = ct_len;
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = hkdf_derive_aes_key(shared_secret, seq, nonce, session_key);
	if (res != TEE_SUCCESS)
		goto out;

	u32_to_be(ct_len, ct_len_be);
	aad[0] = RECORD_VERSION;
	aad[1] = msg_type;
	TEE_MemMove(&aad[2], in + 2, 8);
	TEE_MemMove(&aad[10], nonce, GCM_NONCE_SIZE);
	TEE_MemMove(&aad[22], ct_len_be, 4);

	pt_len = params[1].memref.size;
	res = aes_gcm_decrypt(session_key, nonce, aad, sizeof(aad),
	                      ct, ct_len, tag,
	                      params[1].memref.buffer, &pt_len);
	if (res != TEE_SUCCESS)
		goto out;

	params[1].memref.size = pt_len;
	params[2].value.a = (uint32_t)(seq & 0xffffffffu);
	params[2].value.b = msg_type;
	
	IMSG("message_type = 0x%x", msg_type);
	IMSG("seq = %llu", seq);
	dump_hex("Derived key", session_key, sizeof(session_key));
	dump_hex("Nonce", nonce, GCM_NONCE_SIZE);
	dump_hex("Ciphertext", ct, ct_len);
	dump_hex("Tag", tag, GCM_TAG_SIZE);
	dump_hex("Full packet", in, in_len);

out:
	TEE_MemFill(session_key, 0, sizeof(session_key));
	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	TEE_Result res;

	res = load_or_create_uav_keypair();
	if (res != TEE_SUCCESS)
		return res;

	res = load_peer_pubkey();
	if (res != TEE_SUCCESS)
		IMSG("Station pubkey not set yet");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	if (g_uav_keypair != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(g_uav_keypair);
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
	case TA_DRONE_CMD_EXPORT_PUBKEY:
		return export_pubkey(param_types, params);
	case TA_DRONE_CMD_SET_PEER_PUBKEY:
		return set_peer_pubkey(param_types, params);
	case TA_DRONE_CMD_DECRYPT_PACKET:
		return decrypt_packet(param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
