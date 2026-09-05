#ifndef HOST_FUZZ_SHIM_LINUX_IEEE80211_H
#define HOST_FUZZ_SHIM_LINUX_IEEE80211_H
/* SPDX-License-Identifier: ISC */
/*
 * Host-fuzz shim: symbols extracted verbatim from the shipping kernel's
 * include/linux/ieee80211.h so the frame-inject parser compiles unchanged.
 */
#include "linux_shim.h"
#include <net/ieee80211_radiotap.h>

#define ETH_ALEN 6

#define FCS_LEN 4

#define IEEE80211_FCTL_VERS		0x0003

#define IEEE80211_FCTL_FTYPE		0x000c

#define IEEE80211_FCTL_STYPE		0x00f0

#define IEEE80211_FCTL_TODS		0x0100

#define IEEE80211_FCTL_FROMDS		0x0200

#define IEEE80211_FCTL_MOREFRAGS	0x0400

#define IEEE80211_FCTL_RETRY		0x0800

#define IEEE80211_FCTL_PM		0x1000

#define IEEE80211_FCTL_MOREDATA		0x2000

#define IEEE80211_FCTL_PROTECTED	0x4000

#define IEEE80211_FCTL_ORDER		0x8000

#define IEEE80211_FTYPE_MGMT		0x0000

#define IEEE80211_FTYPE_CTL		0x0004

#define IEEE80211_FTYPE_DATA		0x0008

#define IEEE80211_FTYPE_EXT		0x000c

#define IEEE80211_STYPE_ASSOC_REQ	0x0000

#define IEEE80211_STYPE_ASSOC_RESP	0x0010

#define IEEE80211_STYPE_REASSOC_REQ	0x0020

#define IEEE80211_STYPE_REASSOC_RESP	0x0030

#define IEEE80211_STYPE_PROBE_REQ	0x0040

#define IEEE80211_STYPE_PROBE_RESP	0x0050

#define IEEE80211_STYPE_BEACON		0x0080

#define IEEE80211_STYPE_ATIM		0x0090

#define IEEE80211_STYPE_DISASSOC	0x00A0

#define IEEE80211_STYPE_AUTH		0x00B0

#define IEEE80211_STYPE_DEAUTH		0x00C0

#define IEEE80211_STYPE_ACTION		0x00D0

#define IEEE80211_STYPE_TRIGGER		0x0020

#define IEEE80211_STYPE_PSPOLL		0x00A0

#define IEEE80211_STYPE_RTS		0x00B0

#define IEEE80211_STYPE_CTS		0x00C0

#define IEEE80211_STYPE_ACK		0x00D0

#define IEEE80211_STYPE_CFEND		0x00E0

#define IEEE80211_STYPE_CFENDACK	0x00F0

#define IEEE80211_STYPE_DATA			0x0000

#define IEEE80211_STYPE_NULLFUNC		0x0040

#define IEEE80211_STYPE_QOS_DATA		0x0080

#define IEEE80211_STYPE_QOS_NULLFUNC		0x00C0

#define IEEE80211_STYPE_S1G_BEACON		0x0010

#define IEEE80211_PV1_FCTL_STYPE	0x00e0

#define IEEE80211_QOS_CTL_LEN		2

#define IEEE80211_QOS_CTL_A_MSDU_PRESENT	0x0080

#define IEEE80211_HT_CTL_LEN		4

static inline bool ieee80211_is_data(__le16 fc)
{
	return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE)) ==
	       cpu_to_le16(IEEE80211_FTYPE_DATA);
}

static inline bool ieee80211_is_data_qos(__le16 fc)
{
	/*
	 * mask with QOS_DATA rather than IEEE80211_FCTL_STYPE as we just need
	 * to check the one bit
	 */
	return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_STYPE_QOS_DATA)) ==
	       cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA);
}

static inline bool ieee80211_is_mgmt(__le16 fc)
{
	return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE)) ==
	       cpu_to_le16(IEEE80211_FTYPE_MGMT);
}

static inline bool ieee80211_is_ctl(__le16 fc)
{
	return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE)) ==
	       cpu_to_le16(IEEE80211_FTYPE_CTL);
}

static inline bool ieee80211_is_ext(__le16 fc)
{
	return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE)) ==
	       cpu_to_le16(IEEE80211_FTYPE_EXT);
}

static inline bool ieee80211_has_a4(__le16 fc)
{
	__le16 tmp = cpu_to_le16(IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS);
	return (fc & tmp) == tmp;
}

static inline bool ieee80211_has_order(__le16 fc)
{
	return (fc & cpu_to_le16(IEEE80211_FCTL_ORDER)) != 0;
}


/* Verbatim from the shipping kernel's include/linux/ieee80211.h. */
struct ieee80211_trigger {
	__le16 frame_control;
	__le16 duration;
	u8 ra[ETH_ALEN];
	u8 ta[ETH_ALEN];
	__le64 common_info;
	u8 variable[];
} __packed __aligned(2);

struct ieee80211_ext {
	__le16 frame_control;
	__le16 duration;
	union {
		struct {
			u8 sa[ETH_ALEN];
			__le32 timestamp;
			u8 change_seq;
			u8 variable[0];
		} __packed s1g_beacon;
		struct {
			u8 sa[ETH_ALEN];
			__le32 timestamp;
			u8 change_seq;
			u8 next_tbtt[3];
			u8 variable[0];
		} __packed s1g_short_beacon;
	} u;
} __packed __aligned(2);

/* Ported verbatim from the same kernel's net/wireless/util.c. */
static inline unsigned int __attribute_const__ ieee80211_hdrlen(__le16 fc)
{
	unsigned int hdrlen = 24;

	if (ieee80211_is_ext(fc)) {
		hdrlen = 4;
		goto out;
	}

	if (ieee80211_is_data(fc)) {
		if (ieee80211_has_a4(fc))
			hdrlen = 30;
		if (ieee80211_is_data_qos(fc)) {
			hdrlen += IEEE80211_QOS_CTL_LEN;
			if (ieee80211_has_order(fc))
				hdrlen += IEEE80211_HT_CTL_LEN;
		}
		goto out;
	}

	if (ieee80211_is_mgmt(fc)) {
		if (ieee80211_has_order(fc))
			hdrlen += IEEE80211_HT_CTL_LEN;
		goto out;
	}

	if (ieee80211_is_ctl(fc)) {
		if ((fc & cpu_to_le16(0x00E0)) == cpu_to_le16(0x00C0))
			hdrlen = 10;
		else
			hdrlen = 16;
	}
out:
	return hdrlen;
}

#endif /* HOST_FUZZ_SHIM_LINUX_IEEE80211_H */
