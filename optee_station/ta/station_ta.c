#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "station_ta.h"
#include "station_kdf.h"

#define RECORD_VERSION     0x01
#define GCM_NONCE_SIZE     12
#define GCM_TAG_SIZE       16
#define AES_KEY_BITS       256

TEE_Result TA_CreateEntryPoint(void)
{
	TEE_Result res;

	res = station_kdf_init();
	if (res != TEE_SUCCESS) {
		EMSG("station_kdf_init failed: 0x%x", res);
		return res;
	}

	IMSG("TA init done");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("TA_DestroyEntryPoint");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[4],
                                    void **sess_ctx)
{
	(void)params;
	(void)sess_ctx;

	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
	                              TEE_PARAM_TYPE_NONE,
	                              TEE_PARAM_TYPE_NONE,
	                              TEE_PARAM_TYPE_NONE);
	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("TA session opened");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)sess_ctx;
	IMSG("TA session closed");
}

static void dump_text_chunks(const char *label, const char *text, size_t len)
{
	const size_t chunk_size = 200;
	size_t offset = 0;

	if (!label || !text)
		return;

	IMSG("%s", label);

	while (offset < len) {
		size_t chunk = len - offset;
		if (chunk > chunk_size)
			chunk = chunk_size;

		IMSG("%.*s", (int)chunk, text + offset);
		offset += chunk;
	}
}

static void build_nonce(uint64_t seq, uint8_t nonce[GCM_NONCE_SIZE])
{
	/* 12-byte nonce:
	 * [0..3]  = fixed prefix
	 * [4..11] = seq big-endian
	 */
	nonce[0] = 'L';
	nonce[1] = 'O';
	nonce[2] = 'G';
	nonce[3] = '1';
	u64_to_be(seq, &nonce[4]);
}

static TEE_Result aes_gcm_encrypt(const uint8_t key[DERIVED_KEY_SIZE],
                                  const uint8_t nonce[GCM_NONCE_SIZE],
                                  const uint8_t *aad, uint32_t aad_len,
                                  const uint8_t *plaintext, uint32_t plaintext_len,
                                  uint8_t *ciphertext, uint32_t *ciphertext_len,
                                  uint8_t tag[GCM_TAG_SIZE], uint32_t *tag_len)
{
	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
	TEE_Attribute attr;

	if (!key || !nonce || !plaintext || !ciphertext || !ciphertext_len ||
	    !tag || !tag_len)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM,
	                            TEE_MODE_ENCRYPT, AES_KEY_BITS);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES_KEY_BITS, &key_obj);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
	                     (void *)key, DERIVED_KEY_SIZE);

	res = TEE_PopulateTransientObject(key_obj, &attr, 1);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_SetOperationKey(op, key_obj);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_AEInit(op,
	           (void *)nonce, GCM_NONCE_SIZE,
	           GCM_TAG_SIZE * 8,
	           0, 0);

	if (aad && aad_len > 0)
		TEE_AEUpdateAAD(op, (void *)aad, aad_len);

	res = TEE_AEEncryptFinal(op,
	                         (void *)plaintext, plaintext_len,
	                         ciphertext, ciphertext_len,
	                         tag, tag_len);

out:
	if (key_obj != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_obj);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);

	return res;
}

static TEE_Result process_line(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_VALUE_OUTPUT,
		TEE_PARAM_TYPE_NONE
	);

	TEE_Result res;
	uint64_t seq = 0;
	uint8_t derived_key[DERIVED_KEY_SIZE];
	uint8_t nonce[GCM_NONCE_SIZE];
	uint8_t seq_be[8];
	uint8_t ct_len_be[4];
	uint8_t aad[1 + 8 + 12 + 4]; /* version + seq + nonce + ct_len */
	uint8_t tag[GCM_TAG_SIZE];

	const uint8_t *plaintext;
	uint32_t plaintext_len;
	uint8_t *out;
	uint32_t out_cap;
	uint32_t ciphertext_len;
	uint32_t tag_len = GCM_TAG_SIZE;
	uint32_t needed;
	uint8_t *ciphertext_ptr;
	uint8_t *tag_ptr;

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || params[0].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[1].memref.buffer || params[1].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	plaintext = (const uint8_t *)params[0].memref.buffer;
	plaintext_len = params[0].memref.size;

	res = station_kdf_next_key(&seq, derived_key);
	if (res != TEE_SUCCESS)
		return res;

	build_nonce(seq, nonce);
	u64_to_be(seq, seq_be);
	u32_to_be(plaintext_len, ct_len_be);

	/* AAD = version | seq | nonce | ct_len */
	aad[0] = RECORD_VERSION;
	TEE_MemMove(&aad[1], seq_be, 8);
	TEE_MemMove(&aad[1 + 8], nonce, GCM_NONCE_SIZE);
	TEE_MemMove(&aad[1 + 8 + GCM_NONCE_SIZE], ct_len_be, 4);

	needed = 1 + 8 + GCM_NONCE_SIZE + 4 + plaintext_len + GCM_TAG_SIZE;
	out = (uint8_t *)params[1].memref.buffer;
	out_cap = params[1].memref.size;

	if (out_cap < needed) {
		params[1].memref.size = needed;
		TEE_MemFill(derived_key, 0, sizeof(derived_key));
		return TEE_ERROR_SHORT_BUFFER;
	}

	ciphertext_ptr = out + 1 + 8 + GCM_NONCE_SIZE + 4;
	tag_ptr = ciphertext_ptr + plaintext_len;
	ciphertext_len = plaintext_len;

	res = aes_gcm_encrypt(derived_key, nonce,
	                      aad, sizeof(aad),
	                      plaintext, plaintext_len,
	                      ciphertext_ptr, &ciphertext_len,
	                      tag, &tag_len);
	if (res != TEE_SUCCESS) {
		TEE_MemFill(derived_key, 0, sizeof(derived_key));
		return res;
	}

	/* 封裝 */
	out[0] = RECORD_VERSION;
	TEE_MemMove(out + 1, seq_be, 8);
	TEE_MemMove(out + 1 + 8, nonce, GCM_NONCE_SIZE);
	TEE_MemMove(out + 1 + 8 + GCM_NONCE_SIZE, ct_len_be, 4);
	TEE_MemMove(tag_ptr, tag, GCM_TAG_SIZE);

	params[1].memref.size = 1 + 8 + GCM_NONCE_SIZE + 4 + ciphertext_len + tag_len;
	params[2].value.a = (uint32_t)(seq & 0xFFFFFFFFu);
	params[2].value.b = (uint32_t)((seq >> 32) & 0xFFFFFFFFu);

	IMSG("Encrypted log line, seq=%llu, pt_len=%u, out_len=%u",
	     seq, plaintext_len, params[1].memref.size);
	dump_hex("Derived key:", derived_key, DERIVED_KEY_SIZE);
	dump_hex("Nonce:", nonce, GCM_NONCE_SIZE);
	dump_hex("Ciphertext:", ciphertext_ptr, ciphertext_len);
	dump_hex("Tag:", tag, GCM_TAG_SIZE);

	TEE_MemFill(derived_key, 0, sizeof(derived_key));
	return TEE_SUCCESS;
}

static TEE_Result key_test(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_VALUE_OUTPUT,
		TEE_PARAM_TYPE_NONE
	);

	TEE_Result res;
	uint8_t derived_key[DERIVED_KEY_SIZE];
	uint64_t seq = 0;
	size_t in_len;
	size_t out_cap;
	char *line_buf = NULL;

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || params[0].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[1].memref.buffer || params[1].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/* 為這一行資料派生 key */
	res = station_kdf_next_key(&seq, derived_key);
	if (res != TEE_SUCCESS)
		return res;

	in_len = params[0].memref.size;
	out_cap = params[1].memref.size;

	if (in_len > out_cap) {
		params[1].memref.size = in_len;
		TEE_MemFill(derived_key, 0, sizeof(derived_key));
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* echo 回 CA */
	TEE_MemMove(params[1].memref.buffer, params[0].memref.buffer, in_len);
	params[1].memref.size = in_len;

	params[2].value.a = (uint32_t)(seq & 0xFFFFFFFFu);

	line_buf = TEE_Malloc(in_len + 1, 0);
	if (!line_buf) {
		TEE_MemFill(derived_key, 0, sizeof(derived_key));
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	TEE_MemMove(line_buf, params[0].memref.buffer, in_len);
	line_buf[in_len] = '\0';

	/* 分段輸出，避免單次 IMSG 太長被截斷 */
	IMSG("Seq %lu", seq);
	dump_text_chunks("LOG content:", line_buf, in_len);
	dump_hex("The derived key for this line is:", derived_key, DERIVED_KEY_SIZE);

	TEE_Free(line_buf);
	TEE_MemFill(derived_key, 0, sizeof(derived_key));
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
	(void)sess_ctx;

	switch (cmd_id) {
	case TA_STATION_CMD_PROCESS_LINE:
		return process_line(param_types, params);
	case TA_STATION_CMD_KEY_TEST:
		return key_test(param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
