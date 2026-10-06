// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ut_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/conntrack/cleanupv1"
	"github.com/projectcalico/calico/felix/bpf/conntrack/cttestdata"
	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
)

func TestBPFProgCleanerDoesNotDeleteRevivedIPv6OrphanNATReverse(t *testing.T) {
	RegisterTestingT(t)

	revKey := conntrack.NewKeyV6(
		conntrack.ProtoTCP,
		net.ParseIP("2001:db8::1"), 5555,
		net.ParseIP("2001:db8::2"), 8080,
	)
	leg := conntrack.Leg{SynSeen: true, AckSeen: true}
	staleLastSeen := cttestdata.Now - timeouts.DefaultTimeouts().TCPEstablished - time.Second
	staleValue := conntrack.NewValueV6NATReverse(staleLastSeen, 0, leg, leg, nil, nil, 5555)

	var refreshed bool
	cleanupMap := &ctCleanupRevivalHook{
		MapWithExistsCheck: ctCleanupMapV6.(maps.MapWithExistsCheck),
		afterUpdate: func(key, value []byte) {
			if refreshed || !bytes.Equal(key, revKey.AsBytes()) {
				return
			}
			refreshed = true

			// Check that the IPv6 cleanup queue captured the real timestamp. With
			// the old IPv4 offset this reads as zero and this test would not exercise
			// the timestamp-based revival guard.
			queuedValue := conntrack.CleanupValueV6FromBytes(value)
			Expect(queuedValue.Timestamp()).To(Equal(uint64(staleLastSeen)))

			// Simulate a packet refreshing the entry after the scanner queued its
			// stale timestamp but before the BPF cleaner inspects the queue.
			freshValue := conntrack.NewValueV6NATReverse(cttestdata.Now, 0, leg, leg, nil, nil, 5555)
			Expect(ctMapV6.Update(revKey.AsBytes(), freshValue.AsBytes())).To(Succeed())
		},
	}

	livenessScanner := conntrack.NewLivenessScanner(
		timeouts.DefaultTimeouts(), true, conntrack.WithTimeShim(mocktime.New()),
	)
	cleaner, err := conntrack.NewBPFProgCleaner(6, timeouts.DefaultTimeouts(), conntrack.BPFLogLevelDebug)
	Expect(err).NotTo(HaveOccurred(), "failed to create IPv6 BPF cleaner")
	scanner := conntrack.NewScanner(
		ctMapV6, conntrack.KeyV6FromBytes, conntrack.ValueV6FromBytes,
		nil, "Disabled", cleanupMap, 6, cleaner, livenessScanner,
	)
	clearMaps := func() {
		resetMap(ctMapV6)
		resetMap(ctCleanupMapV6)
	}
	clearMaps()
	t.Cleanup(clearMaps)
	t.Cleanup(func() { scanner.Close() })

	Expect(ctMapV6.Update(revKey.AsBytes(), staleValue.AsBytes())).To(Succeed())
	scanner.Scan()

	Expect(refreshed).To(BeTrue(), "expected the cleanup request to be written before the cleaner ran")
	valueBytes, err := ctMapV6.Get(revKey.AsBytes())
	Expect(err).NotTo(HaveOccurred(), "the refreshed IPv6 conntrack entry should survive cleanup")
	Expect(conntrack.ValueV6FromBytes(valueBytes).LastSeen()).To(Equal(int64(cttestdata.Now)))
	cleanupQueue, err := cleanupv1.LoadMapMemV6(ctCleanupMapV6)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(cleanupQueue)).To(BeZero())
}

type ctCleanupRevivalHook struct {
	maps.MapWithExistsCheck
	afterUpdate func(key, value []byte)
}

func (m *ctCleanupRevivalHook) Update(key, value []byte) error {
	if err := m.MapWithExistsCheck.Update(key, value); err != nil {
		return err
	}
	if m.afterUpdate != nil {
		m.afterUpdate(key, value)
	}
	return nil
}
