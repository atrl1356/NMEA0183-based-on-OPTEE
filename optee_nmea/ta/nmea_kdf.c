#include "nmea_kdf.h"

#define STORAGE_ID TEE_STORAGE_PRIVATE

static const char MASTER_KEY_OBJ_ID[] = "nmea_master_key";
static const char SEQ_OBJ_ID[]        = "nmea_seq_counter";

static uint8_t  g_master_key[MASTER_KEY_SIZE];
static uint64_t g_seq = 0;
static bool     g_kdf_ready = false;

/* ---------- 基本工具 ---------- */

void u32_to_be(uint32_t v, uint8_t out[4])
{
	out[0] = (uint8_t)((v >> 24) & 0xFF);
	out[1] = (uint8_t)((v >> 16) & 0xFF);
	out[2] = (uint8_t)((v >>  8) & 0xFF);
	out[3] = (uint8_t)(v & 0xFF);
}

void u64_to_be(uint64_t v, uint8_t out[8])
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

void dump_hex(const char *label, const uint8_t *buf, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	size_t i, j;
	char line[16 * 3 + 1];

	if (!label || !buf)
		return;

	IMSG("%s (len=%zu)\n", label, len);

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

/* ---------- master key ---------- */

static TEE_Result load_or_create_master_key(void)
{
	TEE_Result res;

	res = read_exact_object(MASTER_KEY_OBJ_ID,
	                        sizeof(MASTER_KEY_OBJ_ID) - 1,
	                        g_master_key, MASTER_KEY_SIZE);
	if (res == TEE_SUCCESS) {
		IMSG("master key loaded");
		dump_hex("MASTER KEY:", g_master_key, MASTER_KEY_SIZE);
		return TEE_SUCCESS;
	}

	if (res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;

	TEE_GenerateRandom(g_master_key, MASTER_KEY_SIZE);

	res = create_object_once(MASTER_KEY_OBJ_ID,
	                         sizeof(MASTER_KEY_OBJ_ID) - 1,
	                         g_master_key, MASTER_KEY_SIZE);
	if (res == TEE_SUCCESS) {
		IMSG("master key created");
		dump_hex("MASTER KEY:", g_master_key, MASTER_KEY_SIZE);
	}

	return res;
}

/* ---------- seq ---------- */

static TEE_Result load_or_create_seq(void)
{
	TEE_Result res;

	res = read_exact_object(SEQ_OBJ_ID,
	                        sizeof(SEQ_OBJ_ID) - 1,
	                        &g_seq, sizeof(g_seq));
	if (res == TEE_SUCCESS) {
		IMSG("seq loaded");
		return TEE_SUCCESS;
	}

	if (res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;

	g_seq = 0;

	res = create_object_once(SEQ_OBJ_ID,
	                         sizeof(SEQ_OBJ_ID) - 1,
	                         &g_seq, sizeof(g_seq));
	if (res == TEE_SUCCESS)
		IMSG("seq created");

	return res;
}

static TEE_Result increment_and_store_seq(uint64_t *new_seq)
{
	TEE_Result res;

	g_seq++;
	res = overwrite_object(SEQ_OBJ_ID,
	                       sizeof(SEQ_OBJ_ID) - 1,
	                       &g_seq, sizeof(g_seq));
	if (res != TEE_SUCCESS)
		return res;

	*new_seq = g_seq;
	return TEE_SUCCESS;
}

/* ---------- HKDF 派生 ---------- */
/*
 * record_key = HKDF-SHA256(
 *     IKM  = master_key,
 *     salt = "NMEA-HKDF-SALT",
 *     info = "NMEA-LOG-V1" || seq_be64
 * )
 *
 * 派生 32 bytes
 */

static TEE_Result hkdf_derive_key(const uint8_t master_key[MASTER_KEY_SIZE],
                                  uint64_t seq,
                                  uint8_t out_key[DERIVED_KEY_SIZE])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle ikm_obj = TEE_HANDLE_NULL;
	TEE_ObjectHandle derived_obj = TEE_HANDLE_NULL;
	TEE_Attribute ikm_attr;
	TEE_Attribute params[3];

	static const uint8_t salt[] = "NMEA-HKDF-SALT";
	static const uint8_t info_prefix[] = "NMEA-LOG-V1";

	uint8_t info[(sizeof(info_prefix) - 1) + 8];
	uint8_t seq_be[8];
	uint8_t derived_tmp[DERIVED_KEY_SIZE];
	uint32_t derived_len = sizeof(derived_tmp);

	u64_to_be(seq, seq_be);
	TEE_MemMove(info, info_prefix, sizeof(info_prefix) - 1);
	TEE_MemMove(info + sizeof(info_prefix) - 1, seq_be, sizeof(seq_be));

	res = TEE_AllocateOperation(&op,
	                            TEE_ALG_HKDF_SHA256_DERIVE_KEY,
	                            TEE_MODE_DERIVE,
	                            MASTER_KEY_SIZE * 8);
	if (res != TEE_SUCCESS) {
		EMSG("hkdf: TEE_AllocateOperation failed: 0x%x", res);
		goto out;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_HKDF_IKM,
	                                  MASTER_KEY_SIZE * 8,
	                                  &ikm_obj);
	if (res != TEE_SUCCESS) {
		EMSG("hkdf: TEE_AllocateTransientObject(IKM) failed: 0x%x", res);
		goto out;
	}

	TEE_InitRefAttribute(&ikm_attr, TEE_ATTR_HKDF_IKM,
	                     (void *)master_key, MASTER_KEY_SIZE);

	res = TEE_PopulateTransientObject(ikm_obj, &ikm_attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("hkdf: TEE_PopulateTransientObject failed: 0x%x", res);
		goto out;
	}

	res = TEE_SetOperationKey(op, ikm_obj);
	if (res != TEE_SUCCESS) {
		EMSG("hkdf: TEE_SetOperationKey failed: 0x%x", res);
		goto out;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
	                                  DERIVED_KEY_SIZE * 8,
	                                  &derived_obj);
	if (res != TEE_SUCCESS) {
		EMSG("hkdf: TEE_AllocateTransientObject(derived) failed: 0x%x", res);
		goto out;
	}

	TEE_InitRefAttribute(&params[0], TEE_ATTR_HKDF_SALT,
	                     (void *)salt, sizeof(salt) - 1);

	TEE_InitRefAttribute(&params[1], TEE_ATTR_HKDF_INFO,
	                     (void *)info, sizeof(info));

	/* HKDF 必要參數：輸出金鑰長度（bytes） */
	TEE_InitValueAttribute(&params[2], TEE_ATTR_HKDF_OKM_LENGTH,
	                       DERIVED_KEY_SIZE, 0);

	TEE_DeriveKey(op, params, 3, derived_obj);

	derived_len = sizeof(derived_tmp);

	res = TEE_GetObjectBufferAttribute(derived_obj,
	                                   TEE_ATTR_SECRET_VALUE,
	                                   derived_tmp, &derived_len);
	if (res != TEE_SUCCESS) {
		EMSG("hkdf: TEE_GetObjectBufferAttribute failed: 0x%x", res);
		goto out;
	}

	if (derived_len != DERIVED_KEY_SIZE) {
		EMSG("hkdf: derived length mismatch: %u", derived_len);
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	TEE_MemMove(out_key, derived_tmp, DERIVED_KEY_SIZE);
	res = TEE_SUCCESS;

out:
	TEE_MemFill(derived_tmp, 0, sizeof(derived_tmp));

	if (derived_obj != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(derived_obj);
	if (ikm_obj != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(ikm_obj);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);

	return res;
}

/* ---------- 對外介面 ---------- */

TEE_Result nmea_kdf_init(void)
{
	TEE_Result res;

	res = load_or_create_master_key();
	if (res != TEE_SUCCESS) {
		EMSG("load_or_create_master_key failed: 0x%x", res);
		return res;
	}

	res = load_or_create_seq();
	if (res != TEE_SUCCESS) {
		EMSG("load_or_create_seq failed: 0x%x", res);
		return res;
	}

	g_kdf_ready = true;
	return TEE_SUCCESS;
}

TEE_Result nmea_kdf_next_key(uint64_t *seq_out,
                             uint8_t out_key[DERIVED_KEY_SIZE])
{
	TEE_Result res;
	uint64_t current_seq = 0;

	if (!g_kdf_ready || !seq_out || !out_key)
		return TEE_ERROR_BAD_STATE;

	res = increment_and_store_seq(&current_seq);
	if (res != TEE_SUCCESS) {
		EMSG("increment_and_store_seq failed: 0x%x", res);
		return res;
	}

	res = hkdf_derive_key(g_master_key, current_seq, out_key);
	if (res != TEE_SUCCESS) {
		EMSG("hkdf_derive_key failed: 0x%x", res);
		return res;
	}

	*seq_out = current_seq;
	return TEE_SUCCESS;
}
