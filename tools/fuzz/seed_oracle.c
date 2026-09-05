// SPDX-License-Identifier: ISC

/*
 * Seed oracle: replays the frozen stage-1 manifest against the host-built
 * parser and requires byte-exact agreement with the recorded per-case
 * parse errno. A mismatch means the host shim (hdrlen/constants) or the
 * parser drifted from the kernel behavior the manifest froze; the fuzz
 * corpus must not start from such a state.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wlan_hdd_frame_inject_radiotap.h"

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static uint8_t *unhex(const char *s, size_t *out_len)
{
	size_t n = strlen(s);
	size_t i;
	uint8_t *buf;

	while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '))
		n--;
	buf = malloc(n / 2 ? n / 2 : 1);
	if (!buf)
		return NULL;
	for (i = 0; i + 1 < n; i += 2) {
		int hi = hexval(s[i]);
		int lo = hexval(s[i + 1]);

		if (hi < 0 || lo < 0) {
			free(buf);
			return NULL;
		}
		buf[i / 2] = (uint8_t)((hi << 4) | lo);
	}
	*out_len = n / 2;
	return buf;
}

int main(int argc, char **argv)
{
	FILE *manifest;
	char line[16384];
	const char *expect_field = "\"current_parser_errno\":";
	char expect_str[32];
	unsigned long cases = 0;
	unsigned long mismatches = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s stage1-cases.jsonl\n", argv[0]);
		return 2;
	}
	manifest = fopen(argv[1], "r");
	if (!manifest) {
		perror("fopen manifest");
		return 2;
	}
	while (fgets(line, sizeof(line), manifest)) {
		char *packet_key = strstr(line, "\"packet_hex\":\"");
		char *errno_key = strstr(line, expect_field);
		char *endp;
		uint8_t *buf;
		size_t len = 0;
		struct wlan_hdd_frame_inject_radiotap parsed;
		long expect;
		int ret;
		char *p;

		if (!packet_key || !errno_key)
			continue;
		packet_key += strlen("\"packet_hex\":\"");
		p = strchr(packet_key, '"');
		if (!p)
			continue;
		*p = '\0';
		buf = unhex(packet_key, &len);
		if (!buf) {
			fprintf(stderr, "bad packet_hex in: %.60s\n", line);
			mismatches++;
			continue;
		}
		errno_key += strlen(expect_field);
		expect = strtol(errno_key, &endp, 10);
		if (endp == errno_key) {
			free(buf);
			continue;
		}
		ret = wlan_hdd_frame_inject_radiotap_parse(buf, len, &parsed);
		cases++;
		if ((long)ret != expect) {
			mismatches++;
			printf("MISMATCH expect=%ld got=%d hex=%.400s\n",
			       expect, ret, packet_key);
		}
		free(buf);
	}
	fclose(manifest);
	snprintf(expect_str, sizeof(expect_str), "%lu", cases);
	printf("seed_oracle_cases=%s mismatches=%lu\n", expect_str, mismatches);
	return mismatches ? 1 : 0;
}
