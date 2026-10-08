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
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
)

func TestConntrackCreateCleansReverseEntryWhenForwardCreateFails(t *testing.T) {
	RegisterTestingT(t)

	resetCTMap(ctMap)
	defer resetCTMap(ctMap)

	_, _, _, _, pktBytes, err := testPacketTCPV4WithPayload(node1ip, 1234, 5678, true, nil)
	Expect(err).NotTo(HaveOccurred())

	runBpfUnitTest(t, "conntrack_create_fwd_fail.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(BeEmpty(), "failed NAT forward creation should roll back the reverse entry")
}
