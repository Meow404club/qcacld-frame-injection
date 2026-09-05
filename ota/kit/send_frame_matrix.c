// SPDX-License-Identifier: ISC

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MAX_PACKET_LEN 512
#define RADIOTAP_LEN 12
#define WORKFLOW_GROUP_PACING_NS 1500000000L

enum radiotap_kind {
	RADIOTAP_HCX_1M,
	RADIOTAP_6M,
	RADIOTAP_BAD_RATE,
	RADIOTAP_HCX_1M_FCS,
};

enum frame_kind {
	FRAME_PROBE,
	FRAME_HCX_PROBE,
	FRAME_AUTH_REQUEST,
	FRAME_AUTH_RESPONSE,
	FRAME_ASSOC_REQUEST,
	FRAME_ASSOC_RESPONSE,
	FRAME_REASSOC_REQUEST,
	FRAME_REASSOC_RESPONSE,
	FRAME_PROBE_RESPONSE,
	FRAME_BEACON,
	FRAME_TIMING_ADVERT,
	FRAME_ATIM,
	FRAME_ACTION,
	FRAME_ACTION_NOACK,
	FRAME_DISASSOC,
	FRAME_DEAUTH,
	FRAME_ORDINARY_DATA,
	FRAME_NULL_DATA,
	FRAME_QOS_NULL,
	FRAME_EAP_REQUEST_ID,
	FRAME_EAPOL_START,
	FRAME_EAPOL_M1_WPA1,
	FRAME_EAPOL_M1_WPA2,
	FRAME_RTS,
	FRAME_BAR,
	FRAME_BLOCK_ACK,
	FRAME_PS_POLL,
	FRAME_CF_END,
	FRAME_CF_END_ACK,
	FRAME_CTS,
	FRAME_ACK,
};

enum workflow_frame_kind {
	WORKFLOW_ASSOC_REQUEST_BROADCAST,
	WORKFLOW_ASSOC_REQUEST_DIRECTED,
	WORKFLOW_AUTH_REQUEST,
	WORKFLOW_PROBE_REQUEST,
	WORKFLOW_PROBE_RESPONSE,
	WORKFLOW_ACK_TO_AP,
	WORKFLOW_ACK_TO_CLIENT,
	WORKFLOW_AUTH_RESPONSE,
	WORKFLOW_ASSOC_RESPONSE,
	WORKFLOW_REASSOC_RESPONSE,
	WORKFLOW_EAPOL_M1_WPA1,
	WORKFLOW_EAPOL_M1_WPA2,
	WORKFLOW_NULL_DATA,
	WORKFLOW_QOS_NULL,
	WORKFLOW_EAPOL_START,
	WORKFLOW_EAP_REQUEST_ID,
	WORKFLOW_DISASSOC,
};

struct variant_spec {
	const char *name;
	enum frame_kind frame_kind;
	enum radiotap_kind radiotap_kind;
	uint8_t expected_type;
	uint8_t expected_subtype;
};

struct workflow_step {
	unsigned int group;
	const char *trigger;
	const char *name;
	enum workflow_frame_kind frame_kind;
	long delay_before_ns;
	uint8_t expected_type;
	uint8_t expected_subtype;
	size_t expected_len;
};

struct workflow_state {
	uint16_t sequence1;
	uint16_t sequence2;
	uint16_t sequence3;
};

static const struct variant_spec variants[] = {
	{ "probe-request", FRAME_PROBE, RADIOTAP_HCX_1M, 0, 4 },
	{ "hcx-probe-request", FRAME_HCX_PROBE, RADIOTAP_HCX_1M, 0, 4 },
	{ "probe-6m", FRAME_PROBE, RADIOTAP_6M, 0, 4 },
	{ "probe-fcs", FRAME_PROBE, RADIOTAP_HCX_1M_FCS, 0, 4 },
	{ "bad-rate-probe", FRAME_PROBE, RADIOTAP_BAD_RATE, 0, 4 },
	{ "auth-request", FRAME_AUTH_REQUEST, RADIOTAP_HCX_1M, 0, 11 },
	{ "auth-response", FRAME_AUTH_RESPONSE, RADIOTAP_HCX_1M, 0, 11 },
	{ "assoc-request", FRAME_ASSOC_REQUEST, RADIOTAP_HCX_1M, 0, 0 },
	{ "assoc-response", FRAME_ASSOC_RESPONSE, RADIOTAP_HCX_1M, 0, 1 },
	{ "reassoc-request", FRAME_REASSOC_REQUEST, RADIOTAP_HCX_1M, 0, 2 },
	{ "reassoc-response", FRAME_REASSOC_RESPONSE, RADIOTAP_HCX_1M, 0, 3 },
	{ "probe-response", FRAME_PROBE_RESPONSE, RADIOTAP_HCX_1M, 0, 5 },
	{ "beacon", FRAME_BEACON, RADIOTAP_HCX_1M, 0, 8 },
	{ "timing-advert", FRAME_TIMING_ADVERT, RADIOTAP_HCX_1M, 0, 6 },
	{ "atim", FRAME_ATIM, RADIOTAP_HCX_1M, 0, 9 },
	{ "action", FRAME_ACTION, RADIOTAP_HCX_1M, 0, 13 },
	{ "action-noack", FRAME_ACTION_NOACK, RADIOTAP_HCX_1M, 0, 14 },
	{ "disassoc", FRAME_DISASSOC, RADIOTAP_HCX_1M, 0, 10 },
	{ "deauth", FRAME_DEAUTH, RADIOTAP_HCX_1M, 0, 12 },
	{ "ordinary-data", FRAME_ORDINARY_DATA, RADIOTAP_HCX_1M, 2, 0 },
	{ "null-data", FRAME_NULL_DATA, RADIOTAP_HCX_1M, 2, 4 },
	{ "qos-null", FRAME_QOS_NULL, RADIOTAP_HCX_1M, 2, 12 },
	{ "eap-request-id", FRAME_EAP_REQUEST_ID, RADIOTAP_HCX_1M, 2, 0 },
	{ "eapol-start", FRAME_EAPOL_START, RADIOTAP_HCX_1M, 2, 0 },
	{ "eapol-m1-wpa1", FRAME_EAPOL_M1_WPA1, RADIOTAP_HCX_1M, 2, 0 },
	{ "eapol-m1-wpa2", FRAME_EAPOL_M1_WPA2, RADIOTAP_HCX_1M, 2, 0 },
	{ "rts", FRAME_RTS, RADIOTAP_HCX_1M, 1, 11 },
	{ "bar", FRAME_BAR, RADIOTAP_HCX_1M, 1, 8 },
	{ "block-ack", FRAME_BLOCK_ACK, RADIOTAP_HCX_1M, 1, 9 },
	{ "ps-poll", FRAME_PS_POLL, RADIOTAP_HCX_1M, 1, 10 },
	{ "cf-end", FRAME_CF_END, RADIOTAP_HCX_1M, 1, 14 },
	{ "cf-end-ack", FRAME_CF_END_ACK, RADIOTAP_HCX_1M, 1, 15 },
	{ "cts", FRAME_CTS, RADIOTAP_HCX_1M, 1, 12 },
	{ "ack", FRAME_ACK, RADIOTAP_HCX_1M, 1, 13 },
};

static const struct workflow_step workflow_steps[] = {
	{ 1, "beacon-or-probe-response", "assoc-request-broadcast",
	  WORKFLOW_ASSOC_REQUEST_BROADCAST, 0, 0, 0, 93 },
	{ 1, "beacon-or-probe-response", "auth-request",
	  WORKFLOW_AUTH_REQUEST, 0, 0, 11, 30 },
	{ 2, "auth-response", "ack-to-ap", WORKFLOW_ACK_TO_AP,
	  WORKFLOW_GROUP_PACING_NS, 1, 13, 10 },
	{ 2, "auth-response", "assoc-request-directed",
	  WORKFLOW_ASSOC_REQUEST_DIRECTED, 0, 0, 0, 93 },
	{ 3, "auth-request", "ack-to-client", WORKFLOW_ACK_TO_CLIENT,
	  WORKFLOW_GROUP_PACING_NS, 1, 13, 10 },
	{ 3, "auth-request", "auth-response",
	  WORKFLOW_AUTH_RESPONSE, 0, 0, 11, 30 },
	{ 4, "assoc-request-wpa2", "ack-to-client", WORKFLOW_ACK_TO_CLIENT,
	  WORKFLOW_GROUP_PACING_NS, 1, 13, 10 },
	{ 4, "assoc-request-wpa2", "assoc-response",
	  WORKFLOW_ASSOC_RESPONSE, 0, 0, 1, 46 },
	{ 4, "assoc-request-wpa2", "eapol-m1-wpa2",
	  WORKFLOW_EAPOL_M1_WPA2, 0, 2, 0, 131 },
	{ 5, "assoc-request-wpa1", "ack-to-client", WORKFLOW_ACK_TO_CLIENT,
	  WORKFLOW_GROUP_PACING_NS, 1, 13, 10 },
	{ 5, "assoc-request-wpa1", "assoc-response",
	  WORKFLOW_ASSOC_RESPONSE, 0, 0, 1, 46 },
	{ 5, "assoc-request-wpa1", "eapol-m1-wpa1",
	  WORKFLOW_EAPOL_M1_WPA1, 0, 2, 0, 131 },
	{ 6, "reassoc-request-wpa2", "ack-to-client", WORKFLOW_ACK_TO_CLIENT,
	  WORKFLOW_GROUP_PACING_NS, 1, 13, 10 },
	{ 6, "reassoc-request-wpa2", "reassoc-response",
	  WORKFLOW_REASSOC_RESPONSE, 0, 0, 3, 46 },
	{ 6, "reassoc-request-wpa2", "eapol-m1-wpa2",
	  WORKFLOW_EAPOL_M1_WPA2, 0, 2, 0, 131 },
	{ 7, "reassoc-request-wpa1", "ack-to-client", WORKFLOW_ACK_TO_CLIENT,
	  WORKFLOW_GROUP_PACING_NS, 1, 13, 10 },
	{ 7, "reassoc-request-wpa1", "reassoc-response",
	  WORKFLOW_REASSOC_RESPONSE, 0, 0, 3, 46 },
	{ 7, "reassoc-request-wpa1", "eapol-m1-wpa1",
	  WORKFLOW_EAPOL_M1_WPA1, 0, 2, 0, 131 },
	{ 8, "assoc-or-reassoc-response", "ack-to-ap", WORKFLOW_ACK_TO_AP,
	  WORKFLOW_GROUP_PACING_NS, 1, 13, 10 },
	{ 8, "assoc-or-reassoc-response", "null-data",
	  WORKFLOW_NULL_DATA, 0, 2, 4, 26 },
	{ 9, "null-data", "ack-to-client", WORKFLOW_ACK_TO_CLIENT,
	  WORKFLOW_GROUP_PACING_NS, 1, 13, 10 },
	{ 9, "null-data", "eapol-m1-wpa2",
	  WORKFLOW_EAPOL_M1_WPA2, 0, 2, 0, 131 },
	{ 10, "qos-null", "ack-to-client", WORKFLOW_ACK_TO_CLIENT,
	  WORKFLOW_GROUP_PACING_NS, 1, 13, 10 },
	{ 10, "qos-null", "eapol-m1-wpa1",
	  WORKFLOW_EAPOL_M1_WPA1, 0, 2, 0, 131 },
	{ 11, "probe-request", "probe-response",
	  WORKFLOW_PROBE_RESPONSE, WORKFLOW_GROUP_PACING_NS, 0, 5, 91 },
	{ 12, "eapol-start", "eap-request-id",
	  WORKFLOW_EAP_REQUEST_ID, WORKFLOW_GROUP_PACING_NS, 2, 0, 41 },
	{ 13, "periodic-scan", "probe-request",
	  WORKFLOW_PROBE_REQUEST, WORKFLOW_GROUP_PACING_NS, 0, 4, 42 },
	{ 14, "beacon-disassoc-path", "disassoc",
	  WORKFLOW_DISASSOC, WORKFLOW_GROUP_PACING_NS, 0, 10, 26 },
	{ 15, "beacon-new-ap-path", "assoc-request-broadcast",
	  WORKFLOW_ASSOC_REQUEST_BROADCAST, WORKFLOW_GROUP_PACING_NS, 0, 0, 93 },
	{ 15, "beacon-new-ap-path", "disassoc",
	  WORKFLOW_DISASSOC, 0, 0, 10, 26 },
	{ 16, "null-data-wpa1", "ack-to-client", WORKFLOW_ACK_TO_CLIENT,
	  WORKFLOW_GROUP_PACING_NS, 1, 13, 10 },
	{ 16, "null-data-wpa1", "eapol-m1-wpa1",
	  WORKFLOW_EAPOL_M1_WPA1, 0, 2, 0, 131 },
	{ 17, "qos-null-wpa2", "ack-to-client", WORKFLOW_ACK_TO_CLIENT,
	  WORKFLOW_GROUP_PACING_NS, 1, 13, 10 },
	{ 17, "qos-null-wpa2", "eapol-m1-wpa2",
	  WORKFLOW_EAPOL_M1_WPA2, 0, 2, 0, 131 },
};

static const uint8_t broadcast[ETH_ALEN] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static const uint8_t hcx_probe_body[] = {
	0x00, 0x00,
	0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
	0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
};

static const uint8_t ofdm_probe_body[] = {
	0x00, 0x00,
	0x01, 0x01, 0x8c,
};

static const uint8_t rates_body[] = {
	0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
};

static const uint8_t workflow_probe_response_ies[] = {
	0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
	0x03, 0x01, 0x00,
	0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
	0x30, 0x14, 0x01, 0x00,
	0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00,
	0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00,
	0x00, 0x0f, 0xac, 0x02,
	0x80, 0x00,
};

static const uint8_t workflow_assoc_response_ies[] = {
	0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
	0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
};

static const uint8_t workflow_ssid[] = "QCACLD-TEST1";

static const uint8_t assoc_request_body[] = {
	0x31, 0x04, 0x05, 0x00,
	0x00, 0x0c, 'Q', 'C', 'A', 'C', 'L', 'D', '-', 'T', 'E', 'S', 'T', '1',
	0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
};

static const uint8_t workflow_assoc_request_tail[] = {
	0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
	0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
	0x30, 0x14, 0x01, 0x00,
	0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00,
	0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00,
	0x00, 0x0f, 0xac, 0x02,
	0x80, 0x00,
	0x46, 0x05, 0x7b, 0x00, 0x02, 0x00, 0x00,
	0x3b, 0x04, 0x51, 0x51, 0x53, 0x54,
};

static const uint8_t eap_request_id[] = {
	0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
	0x01, 0x00, 0x00, 0x05, 0x01, 0x01, 0x00, 0x05, 0x01,
};

static const uint8_t eapol_start[] = {
	0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
	0x02, 0x01, 0x00, 0x00,
};

static void put_le16(uint8_t *dst, uint16_t value)
{
	dst[0] = value & 0xff;
	dst[1] = value >> 8;
}

static uint16_t get_le16(const uint8_t *src)
{
	return (uint16_t)src[0] | ((uint16_t)src[1] << 8);
}

static size_t append_bytes(uint8_t *dst, size_t offset, size_t capacity,
			   const void *src, size_t len)
{
	if (offset > capacity || len > capacity - offset)
		return 0;
	memcpy(dst + offset, src, len);
	return offset + len;
}

static size_t make_mgmt(uint8_t *frame, size_t capacity, uint8_t subtype,
			const uint8_t *addr1, const uint8_t *addr2,
			const uint8_t *addr3, uint16_t sequence,
			const void *body, size_t body_len)
{
	size_t len = 24;

	if (capacity < len)
		return 0;
	memset(frame, 0, len);
	frame[0] = subtype << 4;
	memcpy(frame + 4, addr1, ETH_ALEN);
	memcpy(frame + 10, addr2, ETH_ALEN);
	memcpy(frame + 16, addr3, ETH_ALEN);
	put_le16(frame + 22, sequence);
	if (body_len)
		len = append_bytes(frame, len, capacity, body, body_len);
	return len;
}

static size_t make_data(uint8_t *frame, size_t capacity, uint8_t subtype,
			uint8_t direction, const uint8_t *addr1,
			const uint8_t *addr2, const uint8_t *addr3,
			uint16_t sequence, const void *body, size_t body_len)
{
	size_t len = 24;

	if (capacity < len)
		return 0;
	memset(frame, 0, len);
	frame[0] = (subtype << 4) | 0x08;
	frame[1] = direction;
	memcpy(frame + 4, addr1, ETH_ALEN);
	memcpy(frame + 10, addr2, ETH_ALEN);
	memcpy(frame + 16, addr3, ETH_ALEN);
	put_le16(frame + 22, sequence);
	if (body_len)
		len = append_bytes(frame, len, capacity, body, body_len);
	return len;
}

static uint16_t sequence_for(size_t variant_index, uint16_t nonce)
{
	uint16_t sequence = (nonce + variant_index + 1) & 0x0fff;

	if (!sequence)
		sequence = 1;
	return sequence << 4;
}

static uint16_t duration_for(size_t variant_index, uint16_t nonce)
{
	return 0x2000 | ((nonce + variant_index + 1) & 0x0fff);
}

static size_t build_eapol_m1(uint8_t *payload, size_t capacity, bool wpa1,
			     uint16_t nonce)
{
	const size_t len = 8 + 4 + 95;

	if (capacity < len)
		return 0;
	memset(payload, 0, len);
	memcpy(payload, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8);
	payload[8] = wpa1 ? 1 : 2;
	payload[9] = 3;
	payload[10] = 0;
	payload[11] = 95;
	payload[12] = wpa1 ? 0xfe : 2;
	payload[13] = 0;
	payload[14] = wpa1 ? 0x89 : 0x8a;
	payload[15] = 0;
	payload[16] = wpa1 ? 0x20 : 0x10;
	payload[23] = nonce >> 8;
	payload[24] = nonce & 0xff;
	return len;
}

static uint16_t workflow_sequence_next(uint16_t *counter)
{
	uint16_t sequence = *counter;

	(*counter)++;
	if (*counter > 4095)
		*counter = 1;
	return sequence << 4;
}

static uint8_t workflow_anonce_byte(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return (uint8_t)(*state % 0xff);
}

static size_t build_workflow_eapol_m1(uint8_t *payload, size_t capacity,
				      bool wpa1, uint16_t nonce)
{
	const size_t len = 8 + 4 + 95;
	uint16_t replay_counter = 0xf000 + nonce - 1;
	uint32_t anonce_state = 0x9e3779b9U ^ nonce;
	size_t i;

	if (capacity < len)
		return 0;
	memset(payload, 0, len);
	memcpy(payload, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8);
	payload[8] = wpa1 ? 1 : 2;
	payload[9] = 3;
	payload[10] = 0;
	payload[11] = 95;
	payload[12] = wpa1 ? 0xfe : 2;
	payload[13] = 0;
	payload[14] = wpa1 ? 0x89 : 0x8a;
	payload[15] = 0;
	payload[16] = wpa1 ? 0x20 : 0x10;
	payload[23] = replay_counter >> 8;
	payload[24] = replay_counter & 0xff;
	for (i = 0; i < 32; i++)
		payload[25 + i] = workflow_anonce_byte(&anonce_state);
	return len;
}

static size_t build_workflow_frame(const struct workflow_step *step,
				   const uint8_t interface_mac[ETH_ALEN],
				   const uint8_t peer_mac[ETH_ALEN],
				   uint16_t nonce, uint8_t channel,
				   struct workflow_state *state,
				   uint8_t frame[MAX_PACKET_LEN])
{
	static const uint8_t multicast[ETH_ALEN] = {
		0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,
	};
	uint8_t body[160] = {0};
	size_t body_len = 0;
	size_t len = 0;
	uint16_t sequence;

	switch (step->frame_kind) {
	case WORKFLOW_ASSOC_REQUEST_BROADCAST:
	case WORKFLOW_ASSOC_REQUEST_DIRECTED:
		memcpy(body, "\x31\x04\x05\x00", 4);
		body[4] = 0;
		body[5] = sizeof(workflow_ssid) - 1;
		memcpy(body + 6, workflow_ssid, sizeof(workflow_ssid) - 1);
		body_len = append_bytes(
			body, 6 + sizeof(workflow_ssid) - 1, sizeof(body),
			workflow_assoc_request_tail,
			sizeof(workflow_assoc_request_tail));
		if (!body_len)
			return 0;
		sequence = workflow_sequence_next(&state->sequence2);
		len = make_mgmt(
			frame, MAX_PACKET_LEN, 0, peer_mac,
			step->frame_kind == WORKFLOW_ASSOC_REQUEST_BROADCAST ?
			broadcast : interface_mac,
			peer_mac, sequence, body, body_len);
		break;
	case WORKFLOW_AUTH_REQUEST:
		memcpy(body, "\x00\x00\x01\x00\x00\x00", 6);
		sequence = workflow_sequence_next(&state->sequence2);
		len = make_mgmt(frame, MAX_PACKET_LEN, 11, peer_mac,
				interface_mac, peer_mac, sequence, body, 6);
		break;
	case WORKFLOW_PROBE_REQUEST:
		sequence = workflow_sequence_next(&state->sequence2);
		len = make_mgmt(frame, MAX_PACKET_LEN, 4, broadcast,
				interface_mac, broadcast, sequence,
				hcx_probe_body, sizeof(hcx_probe_body));
		break;
	case WORKFLOW_PROBE_RESPONSE:
	{
		size_t probe_ies_offset;

		body[0] = 1;
		put_le16(body + 8, 0x0400);
		put_le16(body + 10, 0x1431);
		body[12] = 0;
		body[13] = sizeof(workflow_ssid) - 1;
		body_len = append_bytes(body, 14, sizeof(body), workflow_ssid,
						sizeof(workflow_ssid) - 1);
		probe_ies_offset = body_len;
		body_len = append_bytes(body, body_len, sizeof(body),
						workflow_probe_response_ies,
						sizeof(workflow_probe_response_ies));
		if (!body_len)
			return 0;
		body[probe_ies_offset + 12] = channel;
		sequence = workflow_sequence_next(&state->sequence3);
		len = make_mgmt(frame, MAX_PACKET_LEN, 5, interface_mac,
				peer_mac, peer_mac, sequence,
				body, body_len);
		break;
	}
	case WORKFLOW_ACK_TO_AP:
	case WORKFLOW_ACK_TO_CLIENT:
		memset(frame, 0, 10);
		frame[0] = 0xd4;
		memcpy(frame + 4,
		       step->frame_kind == WORKFLOW_ACK_TO_AP ?
		       peer_mac : interface_mac, ETH_ALEN);
		return 10;
	case WORKFLOW_AUTH_RESPONSE:
		memcpy(body, "\x00\x00\x02\x00\x00\x00", 6);
		sequence = workflow_sequence_next(&state->sequence1);
		len = make_mgmt(frame, MAX_PACKET_LEN, 11, interface_mac,
				peer_mac, peer_mac, sequence, body, 6);
		break;
	case WORKFLOW_ASSOC_RESPONSE:
	case WORKFLOW_REASSOC_RESPONSE:
		memcpy(body, "\x31\x14\x00\x00\x01\xc0", 6);
		body_len = append_bytes(body, 6, sizeof(body),
					workflow_assoc_response_ies,
					sizeof(workflow_assoc_response_ies));
		if (!body_len)
			return 0;
		if (step->frame_kind == WORKFLOW_ASSOC_RESPONSE)
			sequence = workflow_sequence_next(&state->sequence1);
		else
			sequence = workflow_sequence_next(&state->sequence3);
		len = make_mgmt(frame, MAX_PACKET_LEN,
				step->frame_kind == WORKFLOW_ASSOC_RESPONSE ? 1 : 3,
				interface_mac, peer_mac, peer_mac,
				sequence, body, body_len);
		break;
	case WORKFLOW_EAPOL_M1_WPA1:
	case WORKFLOW_EAPOL_M1_WPA2:
		body_len = build_workflow_eapol_m1(
			body, sizeof(body),
			step->frame_kind == WORKFLOW_EAPOL_M1_WPA1, nonce);
		if (!body_len)
			return 0;
		len = make_data(frame, MAX_PACKET_LEN, 0, 2, interface_mac,
				peer_mac, peer_mac, 0, body, body_len);
		break;
	case WORKFLOW_NULL_DATA:
		sequence = workflow_sequence_next(&state->sequence1);
		len = make_data(frame, MAX_PACKET_LEN, 4, 1, peer_mac,
				interface_mac, peer_mac, sequence, body, 2);
		break;
	case WORKFLOW_QOS_NULL:
		sequence = workflow_sequence_next(&state->sequence1);
		len = make_data(frame, MAX_PACKET_LEN, 12, 1, peer_mac,
				interface_mac, peer_mac, sequence, body, 2);
		break;
	case WORKFLOW_EAPOL_START:
		sequence = workflow_sequence_next(&state->sequence2);
		len = make_data(frame, MAX_PACKET_LEN, 0, 1, peer_mac,
				interface_mac, multicast, sequence,
				eapol_start, sizeof(eapol_start));
		break;
	case WORKFLOW_EAP_REQUEST_ID:
		len = make_data(frame, MAX_PACKET_LEN, 0, 2, interface_mac,
				peer_mac, peer_mac, 0,
				eap_request_id, sizeof(eap_request_id));
		break;
	case WORKFLOW_DISASSOC:
		memcpy(body, "\x08\x00", 2);
		sequence = workflow_sequence_next(&state->sequence1);
		len = make_mgmt(frame, MAX_PACKET_LEN, 10, interface_mac,
				peer_mac, peer_mac, sequence, body, 2);
		break;
	default:
		return 0;
	}
	if (len)
		put_le16(frame + 2, 0x013a);
	return len;
}

static size_t build_frame(const struct variant_spec *spec, size_t variant_index,
			  const uint8_t interface_mac[ETH_ALEN],
			  const uint8_t peer_mac[ETH_ALEN], uint16_t nonce,
			  uint8_t frame[MAX_PACKET_LEN])
{
	uint8_t body[160] = {0};
	uint8_t multicast[ETH_ALEN] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };
	uint16_t sequence = sequence_for(variant_index, nonce);
	uint16_t duration = duration_for(variant_index, nonce);
	size_t body_len;
	size_t len;

	switch (spec->frame_kind) {
	case FRAME_PROBE:
		return make_mgmt(frame, MAX_PACKET_LEN, 4, broadcast,
				 interface_mac, broadcast, sequence,
				 ofdm_probe_body, sizeof(ofdm_probe_body));
	case FRAME_HCX_PROBE:
		return make_mgmt(frame, MAX_PACKET_LEN, 4, broadcast,
				 interface_mac, broadcast, sequence,
				 hcx_probe_body, sizeof(hcx_probe_body));
	case FRAME_AUTH_REQUEST:
		memcpy(body, "\x00\x00\x01\x00\x00\x00", 6);
		return make_mgmt(frame, MAX_PACKET_LEN, 11, peer_mac,
				 interface_mac, peer_mac, sequence, body, 6);
	case FRAME_AUTH_RESPONSE:
		memcpy(body, "\x00\x00\x02\x00\x00\x00", 6);
		return make_mgmt(frame, MAX_PACKET_LEN, 11, peer_mac,
				 interface_mac, peer_mac, sequence, body, 6);
	case FRAME_ASSOC_REQUEST:
		return make_mgmt(frame, MAX_PACKET_LEN, 0, peer_mac,
				 interface_mac, peer_mac, sequence,
				 assoc_request_body, sizeof(assoc_request_body));
	case FRAME_ASSOC_RESPONSE:
	case FRAME_REASSOC_RESPONSE:
		memcpy(body, "\x31\x04\x00\x00\x01\xc0", 6);
		body_len = append_bytes(body, 6, sizeof(body), rates_body,
					sizeof(rates_body));
		return make_mgmt(frame, MAX_PACKET_LEN,
				 spec->frame_kind == FRAME_ASSOC_RESPONSE ? 1 : 3,
				 peer_mac, interface_mac, interface_mac,
				 sequence, body, body_len);
	case FRAME_REASSOC_REQUEST:
		memcpy(body, "\x31\x04\x05\x00", 4);
		memcpy(body + 4, peer_mac, ETH_ALEN);
		body_len = append_bytes(body, 10, sizeof(body), rates_body,
					sizeof(rates_body));
		return make_mgmt(frame, MAX_PACKET_LEN, 2, peer_mac,
				 interface_mac, peer_mac, sequence, body, body_len);
	case FRAME_PROBE_RESPONSE:
	case FRAME_BEACON:
		memset(body, 0, 8);
		put_le16(body + 8, 100);
		put_le16(body + 10, 0x0431);
		body[12] = 0;
		body[13] = 12;
		memcpy(body + 14, "QCACLD-TEST1", 12);
		body_len = append_bytes(body, 26, sizeof(body), rates_body,
					sizeof(rates_body));
		return make_mgmt(frame, MAX_PACKET_LEN,
				 spec->frame_kind == FRAME_PROBE_RESPONSE ? 5 : 8,
				 spec->frame_kind == FRAME_PROBE_RESPONSE ?
				 peer_mac : broadcast,
				 interface_mac, interface_mac, sequence,
				 body, body_len);
	case FRAME_TIMING_ADVERT:
		memset(body, 0, 10);
		return make_mgmt(frame, MAX_PACKET_LEN, 6, broadcast,
				 interface_mac, interface_mac, sequence, body, 10);
	case FRAME_ATIM:
		return make_mgmt(frame, MAX_PACKET_LEN, 9, peer_mac,
				 interface_mac, peer_mac, sequence, NULL, 0);
	case FRAME_ACTION:
	case FRAME_ACTION_NOACK:
		memcpy(body, "\x04\x09\x00\x13\x37\x01", 6);
		return make_mgmt(frame, MAX_PACKET_LEN,
				 spec->frame_kind == FRAME_ACTION ? 13 : 14,
				 peer_mac, interface_mac, peer_mac,
				 sequence, body, 6);
	case FRAME_DISASSOC:
		memcpy(body, "\x08\x00", 2);
		return make_mgmt(frame, MAX_PACKET_LEN, 10, peer_mac,
				 interface_mac, peer_mac, sequence, body, 2);
	case FRAME_DEAUTH:
		memcpy(body, "\x03\x00", 2);
		return make_mgmt(frame, MAX_PACKET_LEN, 12, peer_mac,
				 interface_mac, peer_mac, sequence, body, 2);
	case FRAME_ORDINARY_DATA:
		memcpy(body, "\xaa\xaa\x03\x00\x00\x00\x88\xb5QCAC", 12);
		put_le16(body + 10, nonce);
		return make_data(frame, MAX_PACKET_LEN, 0, 1, peer_mac,
				 interface_mac, peer_mac, sequence, body, 12);
	case FRAME_NULL_DATA:
		return make_data(frame, MAX_PACKET_LEN, 4, 1, peer_mac,
				 interface_mac, peer_mac, sequence, NULL, 0);
	case FRAME_QOS_NULL:
		memset(body, 0, 2);
		return make_data(frame, MAX_PACKET_LEN, 12, 1, peer_mac,
				 interface_mac, peer_mac, sequence, body, 2);
	case FRAME_EAP_REQUEST_ID:
		return make_data(frame, MAX_PACKET_LEN, 0, 2, peer_mac,
				 interface_mac, interface_mac, sequence,
				 eap_request_id, sizeof(eap_request_id));
	case FRAME_EAPOL_START:
		return make_data(frame, MAX_PACKET_LEN, 0, 1, peer_mac,
				 interface_mac, multicast, sequence,
				 eapol_start, sizeof(eapol_start));
	case FRAME_EAPOL_M1_WPA1:
	case FRAME_EAPOL_M1_WPA2:
		body_len = build_eapol_m1(body, sizeof(body),
				spec->frame_kind == FRAME_EAPOL_M1_WPA1,
				nonce);
		return make_data(frame, MAX_PACKET_LEN, 0, 2, peer_mac,
				 interface_mac, interface_mac, sequence,
				 body, body_len);
	case FRAME_RTS:
	case FRAME_PS_POLL:
	case FRAME_CF_END:
	case FRAME_CF_END_ACK:
		memset(frame, 0, 16);
		frame[0] = (spec->expected_subtype << 4) | 0x04;
		put_le16(frame + 2, spec->frame_kind == FRAME_PS_POLL ?
			 0xc001 : duration);
		memcpy(frame + 4, peer_mac, ETH_ALEN);
		memcpy(frame + 10, interface_mac, ETH_ALEN);
		return 16;
	case FRAME_BAR:
		memset(frame, 0, 20);
		frame[0] = 0x84;
		put_le16(frame + 2, duration);
		memcpy(frame + 4, peer_mac, ETH_ALEN);
		memcpy(frame + 10, interface_mac, ETH_ALEN);
		put_le16(frame + 16, 0x0004);
		put_le16(frame + 18, sequence);
		return 20;
	case FRAME_BLOCK_ACK:
		memset(frame, 0, 28);
		frame[0] = 0x94;
		put_le16(frame + 2, duration);
		memcpy(frame + 4, interface_mac, ETH_ALEN);
		memcpy(frame + 10, peer_mac, ETH_ALEN);
		put_le16(frame + 16, 0x0004);
		put_le16(frame + 18, sequence);
		frame[20] = 1;
		return 28;
	case FRAME_CTS:
	case FRAME_ACK:
		memset(frame, 0, 10);
		frame[0] = (spec->expected_subtype << 4) | 0x04;
		put_le16(frame + 2, duration);
		memcpy(frame + 4, interface_mac, ETH_ALEN);
		return 10;
	}

	len = 0;
	return len;
}

static size_t build_radiotap(enum radiotap_kind kind,
			     uint8_t header[RADIOTAP_LEN])
{
	memset(header, 0, RADIOTAP_LEN);
	header[2] = RADIOTAP_LEN;
	header[4] = 0x06;
	header[5] = 0x80;
	header[8] = kind == RADIOTAP_HCX_1M_FCS ? 0x10 : 0;
	switch (kind) {
	case RADIOTAP_HCX_1M:
	case RADIOTAP_HCX_1M_FCS:
		header[9] = 0x02;
		break;
	case RADIOTAP_6M:
		header[9] = 0x0c;
		break;
	case RADIOTAP_BAD_RATE:
		header[9] = 0x04;
		break;
	}
	header[10] = 0x18;
	return RADIOTAP_LEN;
}

static const struct variant_spec *find_variant(const char *name,
					       size_t *index)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(variants); i++) {
		if (!strcmp(name, variants[i].name)) {
			if (index)
				*index = i;
			return &variants[i];
		}
	}
	return NULL;
}

static int parse_mac(const char *text, uint8_t mac[ETH_ALEN])
{
	unsigned int octet[ETH_ALEN];
	char trailing;
	int i;

	if (!text || sscanf(text, "%x:%x:%x:%x:%x:%x%c",
			 &octet[0], &octet[1], &octet[2],
			 &octet[3], &octet[4], &octet[5], &trailing) != ETH_ALEN)
		return -1;
	for (i = 0; i < ETH_ALEN; i++) {
		if (octet[i] > 0xff)
			return -1;
		mac[i] = (uint8_t)octet[i];
	}
	return 0;
}

static int get_interface_mac(int fd, uint8_t mac[ETH_ALEN])
{
	struct ifreq request = {0};

	snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", "wlan0");
	if (ioctl(fd, SIOCGIFHWADDR, &request) < 0)
		return -1;
	memcpy(mac, request.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}

static void print_hex(const uint8_t *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		printf("%02x", data[i]);
	putchar('\n');
}

static int workflow_addresses_match(
	enum workflow_frame_kind kind, const uint8_t *frame,
	const uint8_t interface_mac[ETH_ALEN],
	const uint8_t peer_mac[ETH_ALEN])
{
	const uint8_t *addr1 = frame + 4;
	const uint8_t *addr2 = frame + 10;
	const uint8_t *addr3 = frame + 16;

	switch (kind) {
	case WORKFLOW_ACK_TO_AP:
		return !memcmp(addr1, peer_mac, ETH_ALEN);
	case WORKFLOW_ACK_TO_CLIENT:
		return !memcmp(addr1, interface_mac, ETH_ALEN);
	case WORKFLOW_ASSOC_REQUEST_BROADCAST:
		return !memcmp(addr1, peer_mac, ETH_ALEN) &&
		       !memcmp(addr2, broadcast, ETH_ALEN) &&
		       !memcmp(addr3, peer_mac, ETH_ALEN);
	case WORKFLOW_ASSOC_REQUEST_DIRECTED:
	case WORKFLOW_AUTH_REQUEST:
	case WORKFLOW_NULL_DATA:
	case WORKFLOW_QOS_NULL:
		return !memcmp(addr1, peer_mac, ETH_ALEN) &&
		       !memcmp(addr2, interface_mac, ETH_ALEN) &&
		       !memcmp(addr3, peer_mac, ETH_ALEN);
	case WORKFLOW_PROBE_REQUEST:
		return !memcmp(addr1, broadcast, ETH_ALEN) &&
		       !memcmp(addr2, interface_mac, ETH_ALEN) &&
		       !memcmp(addr3, broadcast, ETH_ALEN);
	case WORKFLOW_PROBE_RESPONSE:
	case WORKFLOW_AUTH_RESPONSE:
	case WORKFLOW_ASSOC_RESPONSE:
	case WORKFLOW_REASSOC_RESPONSE:
	case WORKFLOW_EAPOL_M1_WPA1:
	case WORKFLOW_EAPOL_M1_WPA2:
	case WORKFLOW_EAP_REQUEST_ID:
	case WORKFLOW_DISASSOC:
		return !memcmp(addr1, interface_mac, ETH_ALEN) &&
		       !memcmp(addr2, peer_mac, ETH_ALEN) &&
		       !memcmp(addr3, peer_mac, ETH_ALEN);
	case WORKFLOW_EAPOL_START:
		return !memcmp(addr1, peer_mac, ETH_ALEN) &&
		       !memcmp(addr2, interface_mac, ETH_ALEN) &&
		       !memcmp(addr3, "\x01\x80\xc2\x00\x00\x03", ETH_ALEN);
	}
	return 0;
}

static int workflow_selftest(void)
{
	static const uint8_t expected_radiotap[RADIOTAP_LEN] = {
		0x00, 0x00, 0x0c, 0x00, 0x06, 0x80,
		0x00, 0x00, 0x00, 0x02, 0x18, 0x00,
	};
	const uint8_t interface_mac[ETH_ALEN] = {
		0x02, 0x13, 0x37, 0x5a, 0x11, 0x7d,
	};
	const uint8_t peer_mac[ETH_ALEN] = {
		0x04, 0x42, 0x1a, 0x2b, 0x3c, 0x4d,
	};
	struct workflow_state state = { 0x321, 0x321, 0x321 };
	uint8_t radiotap[RADIOTAP_LEN];
	uint8_t frame[MAX_PACKET_LEN] = {0};
	const struct workflow_step *step;
	uint16_t fc;
	unsigned int previous_group = 0;
	size_t len;
	size_t i;

	if (ARRAY_SIZE(workflow_steps) != 34)
		return 19;
	if (build_radiotap(RADIOTAP_HCX_1M, radiotap) != RADIOTAP_LEN ||
	    memcmp(radiotap, expected_radiotap, sizeof(expected_radiotap)))
		return 20;
	for (i = 0; i < ARRAY_SIZE(workflow_steps); i++) {
		step = &workflow_steps[i];
		if (!step->group || step->group > 17 ||
		    step->group < previous_group ||
		    (step->group == previous_group && step->delay_before_ns) ||
		    (step->group != previous_group && previous_group &&
		     step->delay_before_ns != WORKFLOW_GROUP_PACING_NS))
			return 25;
		previous_group = step->group;
		len = build_workflow_frame(step, interface_mac, peer_mac,
					   0x321, 149, &state, frame);
		if (len != step->expected_len)
			return 21;
		fc = get_le16(frame);
		if (((fc >> 2) & 3) != step->expected_type ||
		    ((fc >> 4) & 0xf) != step->expected_subtype)
			return 22;
		if (step->frame_kind == WORKFLOW_ACK_TO_AP ||
		    step->frame_kind == WORKFLOW_ACK_TO_CLIENT) {
			if (get_le16(frame + 2) ||
			    !workflow_addresses_match(step->frame_kind, frame,
					      interface_mac, peer_mac))
				return 23;
		} else if (get_le16(frame + 2) != 0x013a) {
			return 24;
		}
		if (!workflow_addresses_match(step->frame_kind, frame,
					      interface_mac, peer_mac))
			return 26;
		if (step->frame_kind == WORKFLOW_PROBE_RESPONSE && frame[62] != 149)
			return 29;
		if (step->expected_type != 1 && len >= 24) {
			bool zero_sequence =
				step->frame_kind == WORKFLOW_EAPOL_M1_WPA1 ||
				step->frame_kind == WORKFLOW_EAPOL_M1_WPA2 ||
				step->frame_kind == WORKFLOW_EAP_REQUEST_ID;

			if (!!get_le16(frame + 22) == zero_sequence)
				return 27;
		}
	}
	if (previous_group != 17)
		return 28;
	return 0;
}

static int run_workflow_frame(int fd, const struct sockaddr_ll *address,
			      const uint8_t interface_mac[ETH_ALEN],
			      const uint8_t peer_mac[ETH_ALEN], uint16_t nonce,
			      unsigned int frame_filter, uint8_t channel)
{
	struct workflow_state state = { nonce, nonce, nonce };
	struct timespec timestamp;
	uint8_t radiotap[RADIOTAP_LEN];
	uint8_t frame[MAX_PACKET_LEN] = {0};
	uint8_t packet[MAX_PACKET_LEN + RADIOTAP_LEN];
	const struct workflow_step *step = NULL;
	size_t radiotap_len;
	size_t frame_len = 0;
	size_t packet_len;
	uint16_t fc = 0;
	ssize_t sent;
	size_t i;

	if (!frame_filter || frame_filter > ARRAY_SIZE(workflow_steps)) {
		fprintf(stderr, "workflow: invalid frame filter %u\n", frame_filter);
		return 2;
	}
	radiotap_len = build_radiotap(RADIOTAP_HCX_1M, radiotap);
	if (radiotap_len != RADIOTAP_LEN) {
		fprintf(stderr, "workflow: failed to build hcxdumptool radiotap\n");
		return 2;
	}
	for (i = 0; i < frame_filter; i++) {
		step = &workflow_steps[i];
		frame_len = build_workflow_frame(step, interface_mac, peer_mac,
						 nonce, channel, &state, frame);
		if (frame_len != step->expected_len) {
			fprintf(stderr,
				"workflow frame %zu (%s): build length %zu, expected %zu\n",
				i + 1, step->name, frame_len, step->expected_len);
			return 2;
		}
		fc = get_le16(frame);
		if (((fc >> 2) & 3) != step->expected_type ||
		    ((fc >> 4) & 0xf) != step->expected_subtype) {
			fprintf(stderr,
				"workflow frame %zu (%s): unexpected frame control 0x%04x\n",
					i + 1, step->name, fc);
			return 2;
		}
	}

	packet_len = radiotap_len + frame_len;
	memcpy(packet, radiotap, radiotap_len);
	memcpy(packet + radiotap_len, frame, frame_len);
	if (clock_gettime(CLOCK_MONOTONIC, &timestamp)) {
		fprintf(stderr, "workflow frame %u (%s): monotonic clock failed: %s\n",
			frame_filter, step->name, strerror(errno));
		return 1;
	}
	sent = sendto(fd, packet, packet_len, 0,
		      (const struct sockaddr *)address, sizeof(*address));
	if (sent < 0) {
		fprintf(stderr,
			"workflow frame %u (%s) monotonic_timestamp=%lld.%09ld: sendto failed: %s\n",
			frame_filter, step->name, (long long)timestamp.tv_sec,
			timestamp.tv_nsec, strerror(errno));
		return 1;
	}
	if (sent != (ssize_t)packet_len) {
		fprintf(stderr,
			"workflow frame %u (%s) monotonic_timestamp=%lld.%09ld: short sendto %zd, expected %zu\n",
			frame_filter, step->name, (long long)timestamp.tv_sec,
			timestamp.tv_nsec, sent, packet_len);
		return 1;
	}

	printf("workflow_packet index=%u group=%u trigger=%s name=%s channel=%u packet_hex=",
	       frame_filter, step->group, step->trigger, step->name, channel);
	print_hex(packet, packet_len);
	printf("workflow_frame index=%u group=%u trigger=%s name=%s monotonic_timestamp=%lld.%09ld channel=%u sendto_count=1 bytes=%zd expected=%zu frame_len=%zu fc=0x%04x type=%u subtype=%u\n",
	       frame_filter, step->group, step->trigger, step->name,
	       (long long)timestamp.tv_sec, timestamp.tv_nsec, channel, sent,
	       packet_len, frame_len, fc, step->expected_type,
	       step->expected_subtype);
	printf("workflow_complete frames=1 groups=1 nonce=%u group_filter=%u frame_filter=%u channel=%u serialization=runner-descriptor-completion-gate-required\n",
	       nonce, step->group, frame_filter, channel);
	if (fflush(stdout)) {
		fprintf(stderr, "workflow: final stdout flush failed: %s\n",
			strerror(errno));
		return 1;
	}
	return 0;
}

static int selftest(void)
{
	const uint8_t interface_mac[ETH_ALEN] = { 0x02, 0x13, 0x37, 0x5a, 0x11, 0x7d };
	const uint8_t peer_mac[ETH_ALEN] = { 0x04, 0x42, 0x1a, 0x2b, 0x3c, 0x4d };
	uint8_t frame[MAX_PACKET_LEN] = {0};
	size_t i;
	size_t len;
	uint16_t fc;
	int workflow_result;

	for (i = 0; i < ARRAY_SIZE(variants); i++) {
		len = build_frame(&variants[i], i, interface_mac, peer_mac,
				  0x321, frame);
		if (!len || len > MAX_PACKET_LEN)
			return 10;
		fc = get_le16(frame);
		if (((fc >> 2) & 3) != variants[i].expected_type ||
		    ((fc >> 4) & 0xf) != variants[i].expected_subtype)
			return 11;
		if (variants[i].expected_type != 1 &&
		    (len < 24 || !get_le16(frame + 22)))
			return 12;
		printf("selftest variant=%s frame_len=%zu fc=0x%04x signature=0x%04x\n",
		       variants[i].name, len, fc,
		       variants[i].expected_type == 1 ? get_le16(frame + 2) :
		       get_le16(frame + 22));
	}
	workflow_result = workflow_selftest();
	if (workflow_result) {
		fprintf(stderr, "workflow selftest failed: %d\n", workflow_result);
		return workflow_result;
	}
	printf("workflow_selftest_passed=%zu groups=17\n",
	       ARRAY_SIZE(workflow_steps));
	printf("selftest_passed=%zu\n", ARRAY_SIZE(variants));
	return 0;
}

static void usage(const char *program)
{
	fprintf(stderr,
		"usage: %s --list | --selftest | --workflow-frame <1..34> <channel-1..255> <ap-mac> <nonce-1..4095> | <variant> <peer-mac> <nonce-1..4095>\n",
		program);
}

int main(int argc, char **argv)
{
	const struct variant_spec *spec = NULL;
	uint8_t radiotap[RADIOTAP_LEN];
	uint8_t frame[MAX_PACKET_LEN] = {0};
	uint8_t packet[MAX_PACKET_LEN + RADIOTAP_LEN + 4];
	uint8_t interface_mac[ETH_ALEN];
	uint8_t peer_mac[ETH_ALEN];
	struct sockaddr_ll address = {0};
	unsigned long nonce_value;
	unsigned int ifindex;
	size_t variant_index = 0;
	size_t radiotap_len;
	size_t frame_len;
	size_t packet_len;
	ssize_t sent;
	char *end;
	bool workflow = false;
	unsigned long workflow_frame_value = 0;
	unsigned long workflow_channel_value = 0;
	int mac_arg = 2;
	int nonce_arg = 3;
	int workflow_result;
	int fd;
	int i;

	if (argc == 2 && !strcmp(argv[1], "--list")) {
		for (i = 0; i < (int)ARRAY_SIZE(variants); i++)
			puts(variants[i].name);
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "--selftest"))
		return selftest();
	if (argc != 4 && argc != 6) {
		usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "--workflow-frame")) {
		char *frame_end;
		char *channel_end;

		if (argc != 6) {
			usage(argv[0]);
			return 2;
		}
		errno = 0;
		workflow_frame_value = strtoul(argv[2], &frame_end, 10);
		if (errno || !*argv[2] || *frame_end || !workflow_frame_value ||
		    workflow_frame_value > ARRAY_SIZE(workflow_steps)) {
			fprintf(stderr, "invalid workflow frame: %s\n", argv[2]);
			return 2;
		}
		errno = 0;
		workflow_channel_value = strtoul(argv[3], &channel_end, 10);
		if (errno || !*argv[3] || *channel_end || !workflow_channel_value ||
		    workflow_channel_value > UINT8_MAX) {
			fprintf(stderr, "invalid workflow channel: %s\n", argv[3]);
			return 2;
		}
		workflow = true;
		mac_arg = 4;
		nonce_arg = 5;
	} else if (argc != 4) {
		usage(argv[0]);
		return 2;
	}
	if (!workflow) {
		spec = find_variant(argv[1], &variant_index);
		if (!spec) {
			fprintf(stderr, "unknown frame variant: %s\n", argv[1]);
			return 2;
		}
	}
	if (parse_mac(argv[mac_arg], peer_mac)) {
		fprintf(stderr, "invalid peer MAC: %s\n", argv[mac_arg]);
		return 2;
	}
	errno = 0;
	nonce_value = strtoul(argv[nonce_arg], &end, 0);
	if (errno || !*argv[nonce_arg] || *end || !nonce_value ||
	    nonce_value > 4095) {
		fprintf(stderr, "invalid nonce: %s\n", argv[nonce_arg]);
		return 2;
	}

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		perror("socket(AF_PACKET)");
		return 1;
	}
	if (get_interface_mac(fd, interface_mac)) {
		perror("ioctl(SIOCGIFHWADDR)");
		close(fd);
		return 1;
	}
	ifindex = if_nametoindex("wlan0");
	if (!ifindex) {
		perror("if_nametoindex(wlan0)");
		close(fd);
		return 1;
	}
	address.sll_family = AF_PACKET;
	address.sll_protocol = htons(ETH_P_ALL);
	address.sll_ifindex = (int)ifindex;
	if (workflow) {
		workflow_result = run_workflow_frame(
			fd, &address, interface_mac, peer_mac, (uint16_t)nonce_value,
			(unsigned int)workflow_frame_value,
			(uint8_t)workflow_channel_value);
		close(fd);
		return workflow_result;
	}

	frame_len = build_frame(spec, variant_index, interface_mac, peer_mac,
				(uint16_t)nonce_value, frame);
	if (!frame_len) {
		close(fd);
		return 2;
	}
	radiotap_len = build_radiotap(spec->radiotap_kind, radiotap);
	packet_len = radiotap_len + frame_len;
	memcpy(packet, radiotap, radiotap_len);
	memcpy(packet + radiotap_len, frame, frame_len);
	if (spec->radiotap_kind == RADIOTAP_HCX_1M_FCS) {
		memset(packet + packet_len, 0xa5, 4);
		packet_len += 4;
	}

	printf("packet_hex=");
	print_hex(packet, packet_len);
	sent = sendto(fd, packet, packet_len, 0,
		      (const struct sockaddr *)&address, sizeof(address));
	if (sent < 0) {
		perror("sendto");
		close(fd);
		return 1;
	}
	printf("variant=%s nonce=%lu sendto_count=1 bytes=%zd expected=%zu frame_len=%zu fc=0x%04x type=%u subtype=%u signature=0x%04x interface_mac=%02x:%02x:%02x:%02x:%02x:%02x peer_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
	       spec->name, nonce_value, sent, packet_len, frame_len,
	       get_le16(frame), spec->expected_type, spec->expected_subtype,
	       spec->expected_type == 1 ? get_le16(frame + 2) :
	       get_le16(frame + 22),
	       interface_mac[0], interface_mac[1], interface_mac[2],
	       interface_mac[3], interface_mac[4], interface_mac[5],
	       peer_mac[0], peer_mac[1], peer_mac[2], peer_mac[3],
	       peer_mac[4], peer_mac[5]);
	close(fd);
	return sent == (ssize_t)packet_len ? 0 : 1;
}
