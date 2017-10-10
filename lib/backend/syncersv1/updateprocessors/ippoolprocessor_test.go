// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package updateprocessors_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/ipip"
)

var _ = Describe("Test the ip pools update processor", func() {
	poolKey1 := model.ResourceKey{
		Kind: apiv2.KindIPPool,
		Name: "name1",
	}
	poolKey2 := model.ResourceKey{
		Kind: apiv2.KindIPPool,
		Name: "name2",
	}
	cidr1str := "1.2.3.0/24"
	cidr2str := "aa:bb:cc::/120"
	poolKeyCidr1 := model.IPPoolKey{
		CIDR: net.MustParseCIDR(cidr1str),
	}
	poolKeyCidr2 := model.IPPoolKey{
		CIDR: net.MustParseCIDR(cidr2str),
	}

	It("should handle conversion of valid ip pools", func() {
		up := updateprocessors.NewIPPoolUpdateProcessor()

		By("converting an IP Pool with minimum configuration")
		res := apiv2.NewIPPool()
		res.Name = poolKey1.Name
		res.Spec.CIDR = cidr1str

		kvps, err := up.Process(&model.KVPair{
			Key: poolKey1,
			Value: res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: poolKeyCidr1,
			Value: &model.IPPool {
				CIDR: poolKeyCidr1.CIDR,
				IPIPInterface: "tunl0",
				IPIPMode: ipip.Always,
				Masquerade: false,
				IPAM: true,
				Disabled: false,
			},
			Revision: "abcde",
		}))

		By("adding another IP pool with the same CIDR (but higher alphanumeric name - no update expected")
		res = apiv2.NewIPPool()
		res.Name = poolKey2.Name
		res.Spec.CIDR = cidr1str
		res.Spec.IPIP = &apiv2.IPIPConfiguration{
			Mode: apiv2.IPIPModeOff,
		}
		res.Spec.NATOutgoing = true
		res.Spec.Disabled = true
		kvps, err = up.Process(&model.KVPair{
			Key: poolKey2,
			Value: res,
			Revision: "1234",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(0))

		By("updating the first pool to have a different CIDR - expect updates for both pools")
		res = apiv2.NewIPPool()
		res.Name = poolKey1.Name
		res.Spec.CIDR = cidr2str
		kvps, err = up.Process(&model.KVPair{
			Key: poolKey1,
			Value: res,
			Revision: "abcdef",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: poolKeyCidr1,
				Value: &model.IPPool {
					CIDR: poolKeyCidr1.CIDR,
					IPIPInterface: "",
					IPIPMode: ipip.Undefined,
					Masquerade: true,
					IPAM: false,
					Disabled: true,
				},
				Revision: "1234",
			},
			{
				Key: poolKeyCidr2,
				Value: &model.IPPool {
					CIDR: poolKeyCidr2.CIDR,
					IPIPInterface: "tunl0",
					IPIPMode: ipip.Always,
					Masquerade: false,
					IPAM: true,
					Disabled: false,
				},
				Revision: "abcdef",
			},
		}))

		By("deleting the first pool")
		kvps, err = up.Process(&model.KVPair{
			Key: poolKey1,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: poolKeyCidr2,
			},
		}))

		By("clearing the cache (by starting sync) and failing to delete the second pool")
		up.SyncStarting()
		kvps, err = up.Process(&model.KVPair{
			Key: poolKey2,
		})
		Expect(err).To(HaveOccurred())
	})

	It("should fail to convert an invalid resource", func() {
		up := updateprocessors.NewIPPoolUpdateProcessor()

		By("trying to convert with the wrong key type")
		res := apiv2.NewIPPool()
		res.Spec.CIDR = cidr1str

		_, err := up.Process(&model.KVPair{
			Key:      model.GlobalBGPPeerKey{
				PeerIP: net.MustParseIP("1.2.3.4"),
			},
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())

		By("trying to convert with the wrong value type")
		wres := apiv2.NewBGPPeer()

		_, err = up.Process(&model.KVPair{
			Key:      poolKey1,
			Value:    wres,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())
	})
})
