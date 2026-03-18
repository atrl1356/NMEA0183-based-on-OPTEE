/* main.c */
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

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --udp <port> [--bind <ip>]\n"
		"Example: %s --udp 10110 --bind 127.0.0.1\n",
		prog, prog);
}

static void dump_hex_ca(const char *label, const uint8_t *buf, size_t len)
{
	size_t i;

	printf("%s\n", label);
	for (i = 0; i < len; i++) {
		printf("%02x ", buf[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	if (len % 16 != 0)
		printf("\n");
}

static void invoke_ta_send_line(TEEC_Session *sess, const char *line)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	/* TA 回傳的資料 */
	char out_buf[8192];

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,   /* param0: input NMEA line */
		TEEC_MEMREF_TEMP_OUTPUT,  /* param1: output */
		TEEC_VALUE_OUTPUT,        /* param2: seq */
		TEEC_NONE
	);

	op.params[0].tmpref.buffer = (void *)line;
	op.params[0].tmpref.size = strlen(line);

	op.params[1].tmpref.buffer = out_buf;
	op.params[1].tmpref.size = sizeof(out_buf);

	res = TEEC_InvokeCommand(sess, TA_NMEA_CMD_PROCESS_LINE, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		warnx("TEEC_InvokeCommand failed 0x%x origin 0x%x", res, err_origin);
		return;
	}

	/* TA 回傳 seq */
	uint32_t seq = op.params[2].value.a;

	/* TA 回傳資料長度會寫回 tmpref.size */
	size_t out_len = op.params[1].tmpref.size;

	printf("[TA seq=%u] ", seq);
	dump_hex_ca("Sealed record:", (const uint8_t *)op.params[1].tmpref.buffer, out_len);
	fflush(stdout);
}

/* 把串流 buffer 內完整的行抓出來處理；剩下半行留到下次 */
static void process_lines_from_stream(char *buf, size_t *len_inout,
                                      TEEC_Session *sess)
{
	size_t len = *len_inout;
	size_t start = 0;

	for (size_t i = 0; i < len; i++) {
		if (buf[i] == '\n') {
			size_t line_len = i - start;
			if (line_len > 0 && buf[start + line_len - 1] == '\r')
				line_len--;

			if (line_len > 0) {
				char *line = (char *)malloc(line_len + 1);
				if (!line) return;

				memcpy(line, &buf[start], line_len);
				line[line_len] = '\0';

				/* 將每行 NMEA 送進 TA */
				invoke_ta_send_line(sess, line);

				free(line);
			}
			start = i + 1;
		}
	}

	/* 搬移剩下未完成的一行 */
	if (start > 0) {
		size_t remaining = len - start;
		memmove(buf, &buf[start], remaining);
		*len_inout = remaining;
	}
}

int main(int argc, char *argv[])
{
	const char *bind_ip = "0.0.0.0";
	int udp_port = -1;

	/* --- parse args --- */
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--udp") && i + 1 < argc) {
			udp_port = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--bind") && i + 1 < argc) {
			bind_ip = argv[++i];
		} else {
			usage(argv[0]);
			return 2;
		}
	}
	if (udp_port < 0) {
		usage(argv[0]);
		return 2;
	}

	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_NMEA_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
	                       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed 0x%x origin 0x%x", res, err_origin);

	/* --- UDP socket listen --- */
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) err(1, "socket");

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)udp_port);
	if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1)
		errx(1, "Invalid bind IP: %s", bind_ip);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		err(1, "bind");

	fprintf(stderr, "[CA] Listening UDP on %s:%d\n", bind_ip, udp_port);

	char stream_buf[8192];
	size_t stream_len = 0;

	while (1) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		int r = select(fd + 1, &rfds, NULL, NULL, NULL);
		if (r < 0) {
			if (errno == EINTR) continue;
			err(1, "select");
		}

		if (FD_ISSET(fd, &rfds)) {
			char pkt[8192];
			ssize_t n = recvfrom(fd, pkt, sizeof(pkt), 0, NULL, NULL);
			if (n < 0) {
				if (errno == EINTR) continue;
				err(1, "recvfrom");
			}

			/* append packet to stream buffer */
			if (stream_len + (size_t)n >= sizeof(stream_buf)) {
				/* overflow risk: reset buffer */
				stream_len = 0;
			}
			memcpy(stream_buf + stream_len, pkt, (size_t)n);
			stream_len += (size_t)n;

			process_lines_from_stream(stream_buf, &stream_len, &sess);
		}
	}

	close(fd);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
