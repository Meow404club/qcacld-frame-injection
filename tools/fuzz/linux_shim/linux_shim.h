/* SPDX-License-Identifier: ISC
 *
 * Host-build shim for qcacld3's frame-injection radiotap parser
 * (wlan_hdd_frame_inject_radiotap.c). The shipping kernel has
 * CONFIG_CFG80211=n, so the driver carries a self-contained parser; this
 * shim mirrors the small kernel-internal surface that parser needs so the
 * same source file compiles on the host under libFuzzer/ASan/UBSan.
 *
 * The shim tree is used via -I so <linux/...>/<net/...> resolve here first;
 * linux/ieee80211.h uses #include_next to keep the UAPI constants from the
 * system linux-libc-dev headers.
 */
#ifndef HOST_FUZZ_LINUX_SHIM_H
#define HOST_FUZZ_LINUX_SHIM_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#define __user
#ifndef static_assert
#include <assert.h>
#endif
#define __deprecated

/* Verbatim from the kernel's include/uapi/linux/struct_types.h. */
#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
	union { \
		struct { MEMBERS } ATTRS; \
		struct TAG { MEMBERS } ATTRS NAME; \
	}

#define U8_MAX ((u8)~0U)
#define IEEE80211_MAX_FRAME_LEN 2352
typedef long ssize_t;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;

#define BIT(nr) (1UL << (nr))
#define ALIGN(x, a) (((x) + ((typeof(x))(a) - 1)) & ~((typeof(x))(a) - 1))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define __force
#define __must_check
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#define module_param(name, type, perm) extern int __shim_##name##_unused
#define MODULE_PARM_DESC(name, desc) extern int __shim_##name##_desc_unused
#define EXPORT_SYMBOL_GPL(sym)
#define __packed __attribute__((packed))
#define __aligned(x) __attribute__((aligned(x)))
#ifndef __attribute_const__
#define __attribute_const__ __attribute__((const))
#endif
#define ETH_ALEN 6
#define U16_MAX ((u16)~0U)
#define U32_MAX ((u32)~0U)
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (a) : (b))


static inline uint16_t get_unaligned_le16(const void *p)
{
	const uint8_t *b = p;

	return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

static inline uint32_t get_unaligned_le32(const void *p)
{
	const uint8_t *b = p;

	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
	       ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static inline void put_unaligned_le16(uint16_t v, void *p)
{
	uint8_t *b = p;

	b[0] = v & 0xff;
	b[1] = (v >> 8) & 0xff;
}

static inline uint16_t get_unaligned_be16(const void *p)
{
	const uint8_t *b = p;

	return ((uint16_t)b[0] << 8) | (uint16_t)b[1];
}

static inline uint16_t cpu_to_le16(uint16_t v) { return v; }
static inline uint16_t le16_to_cpu(uint16_t v) { return v; }

#endif /* HOST_FUZZ_LINUX_SHIM_H */
