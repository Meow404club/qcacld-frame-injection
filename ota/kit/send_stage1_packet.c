// SPDX-License-Identifier: ISC

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>

#define MAX_PACKET_LEN 4096
#define CAPTURE_PACKET_LEN 65536
#define DLT_IEEE802_11_RADIO 127

struct pcap_file_header {
	uint32_t magic;
	uint16_t major;
	uint16_t minor;
	int32_t timezone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t linktype;
};

struct pcap_packet_header {
	uint32_t seconds;
	uint32_t microseconds;
	uint32_t captured;
	uint32_t original;
};

static int hex_nibble(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	if (value >= 'A' && value <= 'F')
		return value - 'A' + 10;
	return -1;
}

static int decode_hex(const char *text, uint8_t *packet, size_t capacity,
		      size_t *packet_len)
{
	size_t text_len;
	size_t i;

	if (!text || !packet || !packet_len)
		return -EINVAL;
	text_len = strlen(text);
	if (!text_len || (text_len & 1))
		return -EINVAL;
	if (text_len / 2 > capacity)
		return -EMSGSIZE;
	for (i = 0; i < text_len; i += 2) {
		int high = hex_nibble(text[i]);
		int low = hex_nibble(text[i + 1]);

		if (high < 0 || low < 0)
			return -EINVAL;
		packet[i / 2] = (uint8_t)(high << 4 | low);
	}
	*packet_len = text_len / 2;
	return 0;
}

static uint16_t get_le16(const uint8_t *data)
{
	return data[0] | (uint16_t)data[1] << 8;
}

static int validate_monitor_packet(const uint8_t *packet, size_t packet_len,
			   uint16_t *radiotap_len, uint16_t *fc)
{
	if (packet_len < 10 || packet[0])
		return -EINVAL;
	*radiotap_len = get_le16(packet + 2);
	if (*radiotap_len < 8 || *radiotap_len > packet_len ||
	    packet_len - *radiotap_len < 2)
		return -EINVAL;
	*fc = get_le16(packet + *radiotap_len);
	return 0;
}

static int run_selftest(void)
{
	uint8_t packet[MAX_PACKET_LEN];
	uint16_t radiotap_len;
	uint16_t fc;
	size_t packet_len;

	if (decode_hex("00000800000000004000", packet, sizeof(packet),
		       &packet_len) || packet_len != 10 ||
	    validate_monitor_packet(packet, packet_len, &radiotap_len, &fc) ||
	    radiotap_len != 8 || fc != 0x0040)
		return 1;
	if (decode_hex("0", packet, sizeof(packet), &packet_len) != -EINVAL ||
	    decode_hex("zz", packet, sizeof(packet), &packet_len) != -EINVAL)
		return 1;
	puts("selftest=PASS valid=1 invalid=2");
	return 0;
}

static int parse_mac(const char *text, uint8_t mac[6])
{
	unsigned int value[6];
	int i;

	if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x", &value[0], &value[1],
		   &value[2], &value[3], &value[4], &value[5]) != 6)
		return -EINVAL;
	for (i = 0; i < 6; i++) {
		if (value[i] > 0xff)
			return -EINVAL;
		mac[i] = (uint8_t)value[i];
	}
	return 0;
}

static int capture_bssid(const char *interface, const char *bssid_text,
			 unsigned int seconds, const char *output)
{
	struct pcap_file_header file_header = {
		.magic = 0xa1b2c3d4, .major = 2, .minor = 4,
		.snaplen = CAPTURE_PACKET_LEN, .linktype = DLT_IEEE802_11_RADIO,
	};
	struct sockaddr_ll address = {0};
	uint8_t *packet = NULL;
	uint8_t bssid[6];
	struct timespec start;
	struct timespec now;
	FILE *stream = NULL;
	unsigned int ifindex;
	unsigned long total = 0;
	unsigned long management = 0;
	unsigned long control = 0;
	unsigned long data = 0;
	unsigned long beacons = 0;
	unsigned long target_beacons = 0;
	int fd = -1;
	int ret = 1;

	if (parse_mac(bssid_text, bssid) || !seconds)
		return 2;
	ifindex = if_nametoindex(interface);
	if (!ifindex)
		return 2;
	packet = malloc(CAPTURE_PACKET_LEN);
	if (!packet)
		goto out;
	stream = fopen(output, "wb");
	if (!stream || fwrite(&file_header, sizeof(file_header), 1, stream) != 1)
		goto out;
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		goto out;
	address.sll_family = AF_PACKET;
	address.sll_protocol = htons(ETH_P_ALL);
	address.sll_ifindex = ifindex;
	if (bind(fd, (const struct sockaddr *)&address, sizeof(address)))
		goto out;
	if (clock_gettime(CLOCK_MONOTONIC, &start))
		goto out;
	for (;;) {
		struct pollfd poll_fd = {.fd = fd, .events = POLLIN};
		struct timeval wallclock;
		struct pcap_packet_header packet_header;
		struct sockaddr_ll from;
		socklen_t from_len = sizeof(from);
		uint16_t radiotap_len;
		uint16_t fc;
		ssize_t length;
		int frame_type;
		int subtype;

		if (clock_gettime(CLOCK_MONOTONIC, &now))
			goto out;
		if ((unsigned long)(now.tv_sec - start.tv_sec) >= seconds)
			break;
		if (poll(&poll_fd, 1, 100) < 0) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (!(poll_fd.revents & POLLIN))
			continue;
		length = recvfrom(fd, packet, CAPTURE_PACKET_LEN, 0,
				  (struct sockaddr *)&from, &from_len);
		if (length <= 0)
			continue;
		/* AF_PACKET taps loop a copy of every OUTGOING frame back to
		 * captures on the same interface - for monitor TX that is
		 * the submitter's own radiotap, not an over-the-air RX
		 * observation (the 2026-09-06 b2a round mis-read 90 such
		 * loopbacks as HT echoes). Only accept packets the interface
		 * actually received. */
		if (from.sll_pkttype == PACKET_OUTGOING)
			continue;
		gettimeofday(&wallclock, NULL);
		packet_header.seconds = (uint32_t)wallclock.tv_sec;
		packet_header.microseconds = (uint32_t)wallclock.tv_usec;
		packet_header.captured = (uint32_t)length;
		packet_header.original = (uint32_t)length;
		if (fwrite(&packet_header, sizeof(packet_header), 1, stream) != 1 ||
		    fwrite(packet, (size_t)length, 1, stream) != 1)
			goto out;
		total++;
		if (validate_monitor_packet(packet, (size_t)length, &radiotap_len, &fc))
			continue;
		if (fc & 3)
			continue;
		frame_type = (fc >> 2) & 3;
		subtype = (fc >> 4) & 15;
		if (frame_type == 0)
			management++;
		else if (frame_type == 1)
			control++;
		else if (frame_type == 2)
			data++;
		if (frame_type == 0 && subtype == 8 &&
		    (size_t)length >= (size_t)radiotap_len + 22) {
			beacons++;
			if (!memcmp(packet + radiotap_len + 16, bssid, 6))
				target_beacons++;
		}
	}
	if (fflush(stream))
		goto out;
	printf("capture=PASS packets=%lu management=%lu control=%lu data=%lu "
	       "beacons=%lu target_beacons=%lu output=%s\n", total, management,
	       control, data, beacons, target_beacons, output);
	ret = target_beacons ? 0 : 4;
out:
	if (fd >= 0)
		close(fd);
	if (stream)
		fclose(stream);
	free(packet);
	return ret;
}

static long long realtime_ns(void)
{
	struct timespec value;

	if (clock_gettime(CLOCK_REALTIME, &value))
		return -1;
	return (long long)value.tv_sec * 1000000000LL + value.tv_nsec;
}

static int inspect_packet(const char *hex, uint8_t *packet, size_t *packet_len,
			  uint16_t *radiotap_len, uint16_t *fc)
{
	int ret;

	ret = decode_hex(hex, packet, MAX_PACKET_LEN, packet_len);
	if (ret)
		return ret;
	return validate_monitor_packet(packet, *packet_len, radiotap_len, fc);
}

int main(int argc, char **argv)
{
	struct sockaddr_ll address = {0};
	uint8_t packet[MAX_PACKET_LEN];
	uint16_t radiotap_len;
	uint16_t fc;
	size_t packet_len;
	unsigned int ifindex;
	ssize_t sent;
	int fd;
	int ret;

	if (argc == 2 && !strcmp(argv[1], "--selftest"))
		return run_selftest();
	if (argc == 2 && !strcmp(argv[1], "--clock")) {
		long long value = realtime_ns();

		if (value < 0)
			return 1;
		printf("%lld\n", value);
		return 0;
	}
	if (argc == 6 && !strcmp(argv[1], "--capture-bssid")) {
		char *end = NULL;
		unsigned long seconds;

		errno = 0;
		seconds = strtoul(argv[4], &end, 10);
		if (errno || !end || *end || !seconds || seconds > 3600)
			return 2;
		return capture_bssid(argv[2], argv[3], (unsigned int)seconds,
				     argv[5]);
	}
	if (argc == 3 && !strcmp(argv[1], "--dry-run")) {
		ret = inspect_packet(argv[2], packet, &packet_len, &radiotap_len,
				     &fc);
		if (ret) {
			fprintf(stderr, "packet_error=%d\n", ret);
			return 2;
		}
		printf("dry_run=PASS packet_len=%zu radiotap_len=%u fc=0x%04x\n",
		       packet_len, radiotap_len, fc);
		return 0;
	}
	if (argc != 4 || strcmp(argv[1], "--send")) {
		fprintf(stderr, "usage: %s --selftest | --clock | --dry-run HEX | --send INTERFACE HEX | --capture-bssid INTERFACE BSSID SECONDS PCAP\n",
			argv[0]);
		return 2;
	}
	ret = inspect_packet(argv[3], packet, &packet_len, &radiotap_len, &fc);
	if (ret) {
		fprintf(stderr, "packet_error=%d\n", ret);
		return 2;
	}
	ifindex = if_nametoindex(argv[2]);
	if (!ifindex) {
		perror("if_nametoindex");
		return 1;
	}
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	address.sll_family = AF_PACKET;
	address.sll_protocol = htons(ETH_P_ALL);
	address.sll_ifindex = ifindex;
	sent = sendto(fd, packet, packet_len, 0,
		      (const struct sockaddr *)&address, sizeof(address));
	close(fd);
	printf("sendto_count=%d packet_len=%zu radiotap_len=%u fc=0x%04x "
	       "wallclock_ns=%lld packet_sha256_source=manifest\n",
	       sent == (ssize_t)packet_len, packet_len, radiotap_len, fc,
	       realtime_ns());
	return sent == (ssize_t)packet_len ? 0 : 1;
}
