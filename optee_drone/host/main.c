#include <arpa/inet.h>
#include <err.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <tee_client_api.h>
#include "drone_ta.h"
#include "proto_common.h"

#define MAX_PACKET    4096
#define MAX_PLAINTEXT 2048

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
	size_t hex_len = strlen(hex);
	if (hex_len != out_len * 2)
		return -1;

	for (size_t i = 0; i < out_len; i++) {
		unsigned int v;
		if (sscanf(&hex[i * 2], "%2x", &v) != 1)
			return -1;
		out[i] = (uint8_t)v;
	}
	return 0;
}

static void print_hex(const uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf("\n");
}

static void usage(const char *prog)
{
	fprintf(stderr,
	        "Usage:\n"
	        "  %s --print-pubkey\n"
	        "  %s --set-peer-pubkey <64hex>\n"
	        "  %s --listen-ip <ip> --listen-port <port>\n",
	        prog, prog, prog);
}

int main(int argc, char *argv[])
{
	int print_pub = 0;
	const char *peer_pub_hex = NULL;
	const char *listen_ip = NULL;
	int listen_port = -1;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--print-pubkey")) {
			print_pub = 1;
		} else if (!strcmp(argv[i], "--set-peer-pubkey") && i + 1 < argc) {
			peer_pub_hex = argv[++i];
		} else if (!strcmp(argv[i], "--listen-ip") && i + 1 < argc) {
			listen_ip = argv[++i];
		} else if (!strcmp(argv[i], "--listen-port") && i + 1 < argc) {
			listen_port = atoi(argv[++i]);
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_DRONE_UUID;
	TEEC_Result res;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
	                       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed 0x%x origin 0x%x", res, err_origin);

	if (print_pub) {
		uint8_t pub[X25519_PUBKEY_SIZE];
		TEEC_Operation op;
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
		                                 TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = pub;
		op.params[0].tmpref.size = sizeof(pub);

		res = TEEC_InvokeCommand(&sess, TA_DRONE_CMD_EXPORT_PUBKEY, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "EXPORT_PUBKEY failed 0x%x origin 0x%x", res, err_origin);

		print_hex(pub, sizeof(pub));
		goto out;
	}

	if (peer_pub_hex) {
		uint8_t peer_pub[X25519_PUBKEY_SIZE];
		TEEC_Operation op;

		if (hex_to_bytes(peer_pub_hex, peer_pub, sizeof(peer_pub)) != 0)
			errx(1, "invalid peer pubkey hex");

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		                                 TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = peer_pub;
		op.params[0].tmpref.size = sizeof(peer_pub);

		res = TEEC_InvokeCommand(&sess, TA_DRONE_CMD_SET_PEER_PUBKEY, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "SET_PEER_PUBKEY failed 0x%x origin 0x%x", res, err_origin);

		printf("Station pubkey stored in drone TA\n");
		goto out;
	}

	if (listen_ip && listen_port >= 0) {
		int fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0)
			err(1, "socket");

		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons((uint16_t)listen_port);
		if (inet_pton(AF_INET, listen_ip, &addr.sin_addr) != 1)
			errx(1, "invalid listen ip");

		if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
			err(1, "bind");

		printf("Drone listening on %s:%d\n", listen_ip, listen_port);

		while (1) {
			uint8_t packet[MAX_PACKET];
			char plaintext[MAX_PLAINTEXT + 1];
			TEEC_Operation op;
			ssize_t n = recvfrom(fd, packet, sizeof(packet), 0, NULL, NULL);
			if (n < 0)
				err(1, "recvfrom");

			memset(&op, 0, sizeof(op));
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
			                                 TEEC_MEMREF_TEMP_OUTPUT,
			                                 TEEC_VALUE_OUTPUT,
			                                 TEEC_NONE);
			op.params[0].tmpref.buffer = packet;
			op.params[0].tmpref.size = (size_t)n;
			op.params[1].tmpref.buffer = plaintext;
			op.params[1].tmpref.size = MAX_PLAINTEXT;

			res = TEEC_InvokeCommand(&sess, TA_DRONE_CMD_DECRYPT_PACKET, &op, &err_origin);
			if (res != TEEC_SUCCESS) {
				fprintf(stderr, "DECRYPT_PACKET failed 0x%x origin 0x%x\n", res, err_origin);
				continue;
			}

			plaintext[op.params[1].tmpref.size] = '\0';
			printf("Decrypted command, seq=%u, message_type=0x%02x: \n%s\n", op.params[2].value.a, op.params[2].value.b, plaintext);
		}
	}

	usage(argv[0]);

out:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
