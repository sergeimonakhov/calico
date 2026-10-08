// Project Calico BPF dataplane programs.
// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#define CALI_UNITTEST_CT_NAT_FWD_FAIL

#include "ut.h"

#include "cali_bpf.h"
#include "conntrack.h"
#include "globals.h"
#include "jump.h"
#include "log.h"
#include "parsing.h"
#include "types.h"

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb)
{
	volatile struct cali_tc_globals *globals = state_get_globals_tc();

	if (!globals) {
		return TC_ACT_SHOT;
	}

	globals->data = __globals.v4;
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.ipheader_len = IP_SIZE,
	);
	struct cali_tc_ctx *ctx = &_ctx;

	ctx->state->flags = 0;
	if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
		return TC_ACT_SHOT;
	}
	if (bpf_load_bytes(ctx, skb_l4hdr_offset(ctx), ctx->scratch->l4, TCP_SIZE)) {
		return TC_ACT_SHOT;
	}

	ctx->state->ip_proto = IPPROTO_TCP;

	ipv46_addr_t client = 0x01010101;
	ipv46_addr_t service = 0x02020202;
	ipv46_addr_t backend = 0x08080808;

	struct ct_create_ctx ct_ctx = {
		.orig_src = client,
		.src = client,
		.orig_dst = service,
		.dst = backend,
		.sport = 1234,
		.dport = 666,
		.orig_sport = 1234,
		.orig_dport = 5678,
		.proto = IPPROTO_TCP,
		.type = CALI_CT_TYPE_NAT_REV,
		.allow_return = true,
	};

	return conntrack_create(ctx, &ct_ctx) ? TC_ACT_SHOT : TC_ACT_UNSPEC;
}
