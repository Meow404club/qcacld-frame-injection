// SPDX-License-Identifier: ISC

/*
 * libFuzzer harness for the qcacld3 frame-injection radiotap/MPDU parser.
 * Compiles the production parser source unchanged on the host under
 * -fsanitize=fuzzer,address,undefined; any out-of-bounds read in the
 * walker, TLV validator, A-MSDU subframe loop, or 802.11 validation is a
 * crash oracle. The parser is pure: no kernel state is touched.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wlan_hdd_frame_inject_radiotap.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct wlan_hdd_frame_inject_radiotap first;
	struct wlan_hdd_frame_inject_radiotap second;
	int ret_a;
	int ret_b;

	if (size > 0xffff)
		return 0;

	ret_a = wlan_hdd_frame_inject_radiotap_parse(data, size, &first);
	ret_b = wlan_hdd_frame_inject_radiotap_parse(data, size, &second);

	/* Determinism: identical input must produce identical classification
	 * and identical derived metadata (pointers excluded). */
	if (ret_a != ret_b)
		abort();
	if (ret_a == 0) {
		if (first.frame_version != second.frame_version ||
		    first.frame_type != second.frame_type ||
		    first.frame_subtype != second.frame_subtype ||
		    first.frame_len != second.frame_len ||
		    first.radiotap_len != second.radiotap_len ||
		    first.has_fcs != second.has_fcs)
			abort();
		if (second.frame_len && !second.frame)
			abort();
	}

	/* With the buffer mirrored, an accepted frame pointer must stay in
	 * bounds for the declared frame window. */
	if (ret_a == 0 && first.frame_len) {
		size_t end = (size_t)(first.frame - data) + first.frame_len;

		if (end > size)
			abort();
	}

	return 0;
}
