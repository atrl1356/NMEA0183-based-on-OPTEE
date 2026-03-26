#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <tee_client_api.h>
#include "station_ta.h"

#define MAX_STREAM_BUF   8192
#define MAX_RECORD_BUF   8192

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --src-port <port> --bind <ip> --dst-ip <ip> --dst-port <port>\n"
		"Example: %s --src-port 10110 --bind 127.0.0.1 --dst-ip 127.0.0.1 --dst-port 20000\n",
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

static int invoke_ta_encrypt_line(TEEC_Session *sess,
                                  const char *line,
                                  uint8_t *out_buf,
                                  size_t out_buf_size,
                                  size_t *out_len,
                                  uint64_t *seq_out)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_VALUE_OUTPUT,
		TEEC_NONE
	);

	op.params[0].tmpref.buffer = (void *)line;
	op.params[0].tmpref.size = strlen(line);

	op.params[1].tmpref.buffer = out_buf;
	op.params[1].tmpref.size = out_buf_size;

	res = TEEC_InvokeCommand(sess, TA_STATION_CMD_PROCESS_LINE, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		warnx("TEEC_InvokeCommand failed 0x%x origin 0x%x", res, err_origin);
		return -1;
	}

	*out_len = op.params[1].tmpref.size;
	*seq_out = ((uint64_t)op.params[2].value.b << 32) | op.params[2].value.a;
	return 0;
}

static int forward_record_udp(int fd, struct sockaddr_in *dst,
                              const uint8_t *record, size_t record_len)
{
	ssize_t n = sendto(fd, record, record_len, 0,
	                   (struct sockaddr *)dst, sizeof(*dst));
	return (n == (ssize_t)record_len) ? 0 : -1;
}

static void process_one_line(TEEC_Session *sess,
                             int forward_fd,
                             struct sockaddr_in *dst_addr,
                             const char *line)
{
	uint8_t out_buf[MAX_RECORD_BUF];
	size_t out_len = 0;
	uint64_t seq = 0;

	if (invoke_ta_encrypt_line(sess, line, out_buf, sizeof(out_buf),
	                           &out_len, &seq) != 0)
		return;

	printf("[Sender CA, seq=%llu] ", (unsigned long long)seq);
	dump_hex_ca("Full sealed record:", out_buf, out_len);

	if (forward_record_udp(forward_fd, dst_addr, out_buf, out_len) != 0)
		warn("sendto(receiver)");
}

static void process_stream_lines(char *buf, size_t *len_inout,
                                 TEEC_Session *sess,
                                 int forward_fd,
                                 struct sockaddr_in *dst_addr)
{
	size_t len = *len_inout;
	size_t start = 0;

	for (size_t i = 0; i < len; i++) {
		if (buf[i] == '\n') {
			size_t line_len = i - start;

			if (line_len > 0 && buf[start + line_len - 1] == '\r')
				line_len--;

			if (line_len > 0) {
				char *line = malloc(line_len + 1);
				if (!line)
					return;

				memcpy(line, &buf[start], line_len);
				line[line_len] = '\0';

				process_one_line(sess, forward_fd, dst_addr, line);
				free(line);
			}

			start = i + 1;
		}
	}

	if (start > 0) {
		size_t remaining = len - start;
		memmove(buf, &buf[start], remaining);
		*len_inout = remaining;
	}
}

int main(int argc, char *argv[])
{
	const char *bind_ip = NULL;
	const char *dst_ip = NULL;
	int src_port = -1;
	int dst_port = -1;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--src-port") && i + 1 < argc) {
			src_port = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--bind") && i + 1 < argc) {
			bind_ip = argv[++i];
		} else if (!strcmp(argv[i], "--dst-ip") && i + 1 < argc) {
			dst_ip = argv[++i];
		} else if (!strcmp(argv[i], "--dst-port") && i + 1 < argc) {
			dst_port = atoi(argv[++i]);
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	if (!bind_ip || !dst_ip || src_port < 0 || dst_port < 0) {
		usage(argv[0]);
		return 2;
	}

	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_STATION_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
	                       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed 0x%x origin 0x%x", res, err_origin);

	int src_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (src_fd < 0)
		err(1, "socket(src)");

	struct sockaddr_in src_addr;
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.sin_family = AF_INET;
	src_addr.sin_port = htons((uint16_t)src_port);
	if (inet_pton(AF_INET, bind_ip, &src_addr.sin_addr) != 1)
		errx(1, "invalid bind ip");

	if (bind(src_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0)
		err(1, "bind(src)");

	int forward_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (forward_fd < 0)
		err(1, "socket(forward)");

	struct sockaddr_in dst_addr;
	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons((uint16_t)dst_port);
	if (inet_pton(AF_INET, dst_ip, &dst_addr.sin_addr) != 1)
		errx(1, "invalid dst ip");

	fprintf(stderr, "[Sender CA] listen %s:%d, forward to %s:%d\n",
	        bind_ip, src_port, dst_ip, dst_port);

	char stream_buf[MAX_STREAM_BUF];
	size_t stream_len = 0;

	while (1) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(src_fd, &rfds);

		int r = select(src_fd + 1, &rfds, NULL, NULL, NULL);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			err(1, "select");
		}

		if (FD_ISSET(src_fd, &rfds)) {
			char pkt[4096];
			ssize_t n = recvfrom(src_fd, pkt, sizeof(pkt), 0, NULL, NULL);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				err(1, "recvfrom");
			}

			if (stream_len + (size_t)n >= sizeof(stream_buf))
				stream_len = 0;

			memcpy(stream_buf + stream_len, pkt, (size_t)n);
			stream_len += (size_t)n;

			process_stream_lines(stream_buf, &stream_len,
			                     &sess, forward_fd, &dst_addr);
		}
	}
}
