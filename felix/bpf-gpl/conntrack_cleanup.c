// Project Calico BPF dataplane programs.
// Copyright (c) 2024 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

/* Log prefix for this program.  log.h only defines CALI_LOG if it is not
 * already set, so this must come before any include. */
#define CALI_LOG(fmt, ...) bpf_log("CT-CLEANER------: " fmt, ## __VA_ARGS__)

#include "cali_bpf.h"
#include "conntrack.h"
#include "conntrack_cleanup.h"
#include "conntrack_types.h"
#include "globals.h"
#include "log.h"
#include "qos.h"

const volatile struct cali_ct_cleanup_globals __globals;

#ifdef CALI_CT_CLEANUP_TEST_RACE
// Test-only hook used by conntrack_cleanup_race_debug_v6.c.  State 1 asks the
// cleaner to refresh the reverse entry after its timestamp comparison; state
// 2 reports that the refresh happened.  This map and hook are absent from
// production objects.
CALI_MAP_NAMED(cali_ct_race, cali_ct_race, ,
	BPF_MAP_TYPE_ARRAY, __u32, __u32, 1, 0);

static CALI_BPF_INLINE void ct_cleanup_test_refresh_after_timestamp_check(
	struct calico_ct_value *rev_ct_value, __u64 now)
{
	__u32 zero = 0;
	volatile __u32 *state = cali_ct_race_lookup_elem(&zero);
	if (!state || *state != 1) {
		return;
	}
	// Reproduce the packet path's write to last_seen at this exact point.
	*(volatile __u64 *)&rev_ct_value->last_seen = now;
	*state = 2;
}
#endif

// Context for the conntrack map iteration functions.
//
// WARNING: this struct is returned to user space as the result of the BPF
// program and so must be kept in sync with the equivalent struct in
// bpf_scanner.go.
struct ct_iter_ctx {
	__u64 now;
	__u64 end_time;

	__u64 num_cleaned;
};

// process_ccq_entry processes an entry in the "cleanup queue" map. The map
// is keyed with conntrack key which the userspace cleaner sees as expired.
// The value has <rev_key>:<last_seen_ts>:<rev_last_seen_ts>
// The rev_key is dummy for Normal and reverse entries and is valid for Forward entry.
static long process_ccq_entry(void *map, struct calico_ct_key *key, struct cali_ccq_value *value, void *ctx)
{
	struct ct_iter_ctx *ictx = ctx;
	struct calico_ct_value *actual_ct_value;

	// If the entry is a normal entry, compare the timestamps and delete the key.
	// If the entry is a reverse entry, compare the timestamps and delete the key.
	if (!value->rev_key.protocol) {
		actual_ct_value = cali_ct_lookup_elem(key);
		if (actual_ct_value && (actual_ct_value->last_seen == value->last_seen)) {
			// Decrement the per-pod connlimit counter if this entry
			// carried one of the CONNLIMIT_* flags and the packet
			// path didn't already decrement.
			qos_connlimit_decrement_for_ct(actual_ct_value);
			if (!cali_ct_delete_elem(key)) {
				ictx->num_cleaned++;
			}
		}
	} else {
		// Its a NAT forward entry with a valid reverse key.
		struct calico_ct_value *nat_fwd_value = cali_ct_lookup_elem(key);
		struct calico_ct_key *rev_key = &value->rev_key;
		// Check if the fwd key still points to the same reverse key.
		if (nat_fwd_value) {
			struct calico_ct_key *nat_rev_key = &nat_fwd_value->nat_rev_key;
			if (__builtin_memcmp(nat_rev_key, rev_key, sizeof(struct calico_ct_key))) {
		       		goto delete;
			}
		}
		struct calico_ct_value *rev_ct_value = cali_ct_lookup_elem(rev_key);
		if (rev_ct_value && (rev_ct_value->last_seen == value->rev_last_seen)) {
#ifdef CALI_CT_CLEANUP_TEST_RACE
			ct_cleanup_test_refresh_after_timestamp_check(rev_ct_value, ictx->now);
#endif
			// The reverse leg holds the connlimit flags + ifindex.
			qos_connlimit_decrement_for_ct(rev_ct_value);
			if (!cali_ct_delete_elem(rev_key)) {
				ictx->num_cleaned++;
			}
			if (!cali_ct_delete_elem(key)) {
				ictx->num_cleaned++;
			}
		}
	}
delete:
	cali_ccq_delete_elem(key);
	return 0;
}

// conntrack_cleanup is a BPF program that cleans up expired conntrack entries.
// The expired entries are added to the cleanup_map from the userspace.
// The cleaner does a single pass of the conntrack cleanup map.
// It checks the following and deletes the entries.
// * entry's last_seen is same as the one recorded by the userspace scanner.
// * Does the NAT forward entry still point to the same reverse entry as seen by
//   the userspace.
__attribute__((section("tc"))) int conntrack_cleanup(struct __sk_buff *skb)
{
	struct ct_iter_ctx ictx = {};
	bpf_skb_load_bytes(skb, 0, &ictx, sizeof(ictx));
	if (ictx.now == 0) {
		// Caller didn't provide a fixed time (as used in tests), use current
		// time.
		ictx.now = bpf_ktime_get_ns();
	}
	CALI_DEBUG("Scanning conntrack cleanup map for entries to be cleaned up...");
	bpf_for_each_map_elem(&CCQ_MAP_V, process_ccq_entry, &ictx, 0);
	// Give detailed stats back to userspace.
	ictx.end_time = bpf_ktime_get_ns();
	bpf_skb_store_bytes(skb, 0, &ictx, sizeof(ictx), 0);
	return 0;
}
