/* nmea_ta.c */
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "nmea_ta.h"

static uint32_t g_seq = 0;

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("TA_CreateEntryPoint");
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

	IMSG("NMEA TA session opened");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)sess_ctx;
	IMSG("NMEA TA session closed");
}

static TEE_Result process_line(uint32_t param_types, TEE_Param params[4])
{
	/* param0: input memref (NMEA line)
	 * param1: output memref (echo / future sealed record)
	 * param2: value output (seq)
	 */
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
	                              TEE_PARAM_TYPE_MEMREF_OUTPUT,
	                              TEE_PARAM_TYPE_VALUE_OUTPUT,
	                              TEE_PARAM_TYPE_NONE);

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || params[0].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/* seq++ */
	g_seq++;
	params[2].value.a = g_seq;

	/* echo copy */
	size_t in_len = params[0].memref.size;
	size_t out_cap = params[1].memref.size;

	if (!params[1].memref.buffer || out_cap == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (in_len > out_cap) {
		/* 回報需要的大小 */
		params[1].memref.size = in_len;
		return TEE_ERROR_SHORT_BUFFER;
	}

	TEE_MemMove(params[1].memref.buffer, params[0].memref.buffer, in_len);
	params[1].memref.size = in_len;
	char *out_buf = (char *)params[1].memref.buffer;
	*(out_buf+in_len) = '\0';

	/* debug */
	DMSG("Processed NMEA line %s, seq=%u", out_buf, g_seq);

	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
	(void)sess_ctx;

	switch (cmd_id) {
	case TA_NMEA_CMD_PROCESS_LINE:
		return process_line(param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
