#include <arpa/inet.h>
#include <err.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <tee_client_api.h>
#include "station_ta.h"
#include "proto_common.h"

#define MAX_PACKET_SIZE 4096

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
	size_t hex_len = strlen(hex);
	if (hex_len != out_len * 2) return -1;
	for (size_t i = 0; i < out_len; i++) {
		unsigned int v;
		if (sscanf(&hex[i * 2], "%2x", &v) != 1) return -1;
		out[i] = (uint8_t)v;
	}
	return 0;
}

static void print_hex(const uint8_t *buf, size_t len) {
	for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
	printf("\n");
}

int main(int argc, char *argv[]) {
	int print_pub = 0;
	const char *peer_pub_hex = NULL;
	
	/* 單次發送測試參數 */
	const char *cmd = NULL;
	
	/* 🚀 新增：連續加密代理模式參數 */
	int proxy_port = -1; 
	const char *dst_ip = NULL;
	int dst_port = -1;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--print-pubkey")) print_pub = 1;
		else if (!strcmp(argv[i], "--set-peer-pubkey") && i + 1 < argc) peer_pub_hex = argv[++i];
		else if (!strcmp(argv[i], "--send-cmd") && i + 1 < argc) cmd = argv[++i];
		else if (!strcmp(argv[i], "--proxy-port") && i + 1 < argc) proxy_port = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--dst-ip") && i + 1 < argc) dst_ip = argv[++i];
		else if (!strcmp(argv[i], "--dst-port") && i + 1 < argc) dst_port = atoi(argv[++i]);
	}

	TEEC_Context ctx; TEEC_Session sess; TEEC_Result res; uint32_t err_origin;
	TEEC_UUID uuid = TA_STATION_UUID;
	TEEC_InitializeContext(NULL, &ctx);
	TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	/* 1. 印出公鑰 */
	if (print_pub) {
		uint8_t pub[X25519_PUBKEY_SIZE];
		TEEC_Operation op; memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = pub; op.params[0].tmpref.size = sizeof(pub);
		TEEC_InvokeCommand(&sess, TA_STATION_CMD_EXPORT_PUBKEY, &op, &err_origin);
		print_hex(pub, sizeof(pub));
		goto out;
	}

	/* 2. 設定對方公鑰 */
	if (peer_pub_hex) {
		uint8_t peer_pub[X25519_PUBKEY_SIZE];
		hex_to_bytes(peer_pub_hex, peer_pub, sizeof(peer_pub));
		TEEC_Operation op; memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = peer_pub; op.params[0].tmpref.size = sizeof(peer_pub);
		TEEC_InvokeCommand(&sess, TA_STATION_CMD_SET_PEER_PUBKEY, &op, &err_origin);
		printf("Peer pubkey stored.\n");
		goto out;
	}

	/* 3. 🚀 連續加密代理模式 (無人機明文 -> 加密 -> 傳給接收端) */
	if (proxy_port > 0 && dst_ip && dst_port > 0) {
		int fd_in = socket(AF_INET, SOCK_DGRAM, 0);
		struct sockaddr_in addr_in; memset(&addr_in, 0, sizeof(addr_in));
		addr_in.sin_family = AF_INET; addr_in.sin_port = htons(proxy_port); addr_in.sin_addr.s_addr = INADDR_ANY;
		bind(fd_in, (struct sockaddr *)&addr_in, sizeof(addr_in));

		int fd_out = socket(AF_INET, SOCK_DGRAM, 0);
		struct sockaddr_in addr_out; memset(&addr_out, 0, sizeof(addr_out));
		addr_out.sin_family = AF_INET; addr_out.sin_port = htons(dst_port);
		inet_pton(AF_INET, dst_ip, &addr_out.sin_addr);

		printf("[Encryptor] Listening for Plaintext MAVLink on 0.0.0.0:%d\n", proxy_port);
		printf("[Encryptor] Forwarding Ciphertext to %s:%d\n", dst_ip, dst_port);

		while (1) {
			uint8_t plain[MAX_PACKET_SIZE];
			uint8_t cipher[MAX_PACKET_SIZE];
			ssize_t n = recvfrom(fd_in, plain, sizeof(plain), 0, NULL, NULL);
			if (n <= 0) continue;

			TEEC_Operation op; memset(&op, 0, sizeof(op));
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_OUTPUT, TEEC_NONE);
			op.params[0].tmpref.buffer = plain; op.params[0].tmpref.size = n;
			op.params[1].tmpref.buffer = cipher; op.params[1].tmpref.size = sizeof(cipher);

			res = TEEC_InvokeCommand(&sess, TA_STATION_CMD_ENCRYPT_COMMAND, &op, &err_origin);
			if (res == TEEC_SUCCESS) {
				sendto(fd_out, cipher, op.params[1].tmpref.size, 0, (struct sockaddr *)&addr_out, sizeof(addr_out));
				// printf("[Encryptor] Encrypted %zd bytes -> %zu bytes\n", n, op.params[1].tmpref.size);
			}
		}
	}

out:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
