// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

// Compile the production conntrack cleaner with a test-only pause point after
// the timestamp comparison, so the Go BPF UT can deterministically refresh a
// conntrack entry before the cleaner deletes it.
#define IPVER6
#define CALI_CT_CLEANUP_TEST_RACE
#include "../conntrack_cleanup.c"
