/* main.c - 二進位 MAVLink 專用版 */
#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <tee_client_api.h>
#include "nmea_ta.h"

static void invoke_ta_send_raw(TEEC_Session *sess, const char *data, size_t len)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	char out_buf[2048];

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_OUTPUT, TEEC_NONE);

	op.params[0].tmpref.buffer = (void *)data;
	op.params[0].tmpref.size = len;
	op.params[1].tmpref.buffer = out_buf;
	op.params[1].tmpref.size = sizeof(out_buf);

	res = TEEC_InvokeCommand(sess, TA_NMEA_CMD_PROCESS_LINE, &op, &err_origin);
	if (res != TEEC_SUCCESS) return;

	uint32_t seq = op.params[2].value.a;
	printf("[TA seq=%u] 成功接收並處理了 %zu bytes 的二進位封包！\n", seq, op.params[1].tmpref.size);
	fflush(stdout);
}

int main(int argc, char *argv[])
{
	const char *bind_ip = "0.0.0.0";
	int udp_port = 10110;

	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_NMEA_UUID;
	uint32_t err_origin;

	TEEC_InitializeContext(NULL, &ctx);
	TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)udp_port);
	inet_pton(AF_INET, bind_ip, &addr.sin_addr);
	bind(fd, (struct sockaddr *)&addr, sizeof(addr));

	printf("[CA] Listening UDP on %s:%d (Binary Mode)\n", bind_ip, udp_port);
	fflush(stdout);

	while (1) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		select(fd + 1, &rfds, NULL, NULL, NULL);

		if (FD_ISSET(fd, &rfds)) {
			char pkt[2048];
			ssize_t n = recvfrom(fd, pkt, sizeof(pkt), 0, NULL, NULL);
			if (n > 0) invoke_ta_send_raw(&sess, pkt, (size_t)n);
		}
	}
	return 0;
}