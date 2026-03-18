#ifndef NMEA_KDF_H
#define NMEA_KDF_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <stdint.h>

#define MASTER_KEY_SIZE        32
#define DERIVED_KEY_SIZE       32
#define NMEA_KDF_VERSION       1

void dump_hex(const char *label, const uint8_t *buf, size_t len);
void u32_to_be(uint32_t v, uint8_t out[4]);
void u64_to_be(uint64_t v, uint8_t out[8]);
TEE_Result nmea_kdf_init(void);
TEE_Result nmea_kdf_next_key(uint64_t *seq_out,
                             uint8_t out_key[DERIVED_KEY_SIZE]);

#endif
