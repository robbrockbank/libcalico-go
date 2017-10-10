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
	"github.com/satori/go.uuid"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/libcalico-go/lib/net"
)

var _ = Describe("Test the conflict resolving cache", func() {

	// Define a common set of keys and values for our tests.  Note the actual value
	// types are not important - but make sure we have something non-nil to indicate
	// a value is present.
	key1 := model.GlobalBGPPeerKey{
		PeerIP: net.MustParseIP("1.2.3.4"),
	}
	key2 := model.NodeBGPPeerKey{
		PeerIP:   net.MustParseIP("1.2.3.4"),
		Nodename: "node1",
	}
	/*
		key3 := model.GlobalBGPPeerKey{
			PeerIP: net.MustParseIP("aa:bb::ff"),
		}
		key4 := model.NodeBGPPeerKey{
			PeerIP: net.MustParseIP("aa:bb:cc:dd:ee::"),
			Nodename: "node2",
		}
	*/

	// Share the cache between tests to ensure the clear cache processing is functioning.
	c := updateprocessors.NewConflictResolvingCache()
	BeforeEach(func() {
		c.ClearCache()
	})

	It("should handle add, update and delete when there are no conflicts", func() {
		By("adding a new entry (name1 / key1) and expecting the same result returned")
		kvp := addModifyKVP(key1)
		r, err := c.AddOrModify("name1", kvp)
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(HaveLen(1))
		Expect(r[0]).To(Equal(kvp))

		By("updating the entry (name1 / key1) and expecting the same result returned")
		kvp = addModifyKVP(key1)
		r, err = c.AddOrModify("name1", kvp)
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(HaveLen(1))
		Expect(r[0]).To(Equal(kvp))

		By("deleting the entry name1 and expecting the delete response for that key")
		r, err = c.Delete("name1")
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(HaveLen(1))
		Expect(r[0].Revision).To(Equal(""))
		Expect(r[0].Value).To(BeNil())
		Expect(r[0].Key).To(Equal(key1))
	})

	It("should handle invalid keys gracefully", func() {
		By("adding an entry with an invalid key")
		kvp := addModifyKVP(model.NodeBGPPeerKey{})
		_, err := c.AddOrModify("name1", kvp)
		Expect(err).To(HaveOccurred())
	})

	It("should handle unknown entries in a delete gracefully", func() {
		By("calling delete with an unknown name")
		_, err := c.Delete("name1")
		Expect(err).To(HaveOccurred())
	})

	It("should handle changing the v1 keys for a given v2 resource", func() {
		By("adding a new entry (name1 w/ key1) and expecting the same result returned")
		kvp1 := addModifyKVP(key1)
		r, err := c.AddOrModify("name1", kvp1)
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(HaveLen(1))
		Expect(r[0]).To(Equal(kvp1))

		By("updating the entry (name1 -> key2) and expecting a delete for key1 and an add for key2")
		kvp2 := addModifyKVP(key2)
		r, err = c.AddOrModify("name1", kvp2)
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(Equal([]*model.KVPair{
			{
				Key: key1,
			},
			kvp2,
		}))

		By("deleting the entry name1 and expecting the delete response for key2")
		r, err = c.Delete("name1")
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(HaveLen(1))
		Expect(r[0].Revision).To(Equal(""))
		Expect(r[0].Value).To(BeNil())
		Expect(r[0].Key).To(Equal(key2))

		By("failing to delete the same entry")
		r, err = c.Delete("name1")
		Expect(err).To(HaveOccurred())
	})

	It("should handle multiple names using the same key", func() {
		By("adding a new entry (name2 w/ key1) and expecting the same result returned")
		kvp2 := addModifyKVP(key1)
		r, err := c.AddOrModify("name2", kvp2)
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(HaveLen(1))
		Expect(r[0]).To(Equal(kvp2))

		By("adding a new entry (name1 w/ key1) and expecting key result to be updated: this becomes the active conflicting resource for key1")
		kvp1 := addModifyKVP(key1)
		r, err = c.AddOrModify("name1", kvp1)
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(HaveLen(1))
		Expect(r[0]).To(Equal(kvp1))

		By("adding a new entry (name3 w/ key1) and expecting no results: name1 is the active conflicting resource for key1")
		kvp3 := addModifyKVP(key1)
		r, err = c.AddOrModify("name3", kvp3)
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(HaveLen(0))

		By("updating the entry (name2 -> key2) and expecting an add for key2: no delete for key1 since name1 is active resource for key1")
		kvp2 = addModifyKVP(key2)
		r, err = c.AddOrModify("name2", kvp2)
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(HaveLen(1))
		Expect(r[0]).To(Equal(kvp2))

		By("updating the entry (name1 -> key2) and expecting an updated key1 (name3 active now) and an updated key2 (name1 active now)")
		kvp1 = addModifyKVP(key2)
		r, err = c.AddOrModify("name1", kvp1)
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(Equal([]*model.KVPair{
			kvp3,
			kvp1,
		}))

		By("deleting the entry name1 and expecting an update for key2 (name2 active now)")
		r, err = c.Delete("name1")
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(HaveLen(1))
		Expect(r[0]).To(Equal(kvp2))

		By("deleting the entry name2 and expecting a delete for key2")
		r, err = c.Delete("name2")
		Expect(err).ToNot(HaveOccurred())
		Expect(r).To(HaveLen(1))
		Expect(r[0].Revision).To(Equal(""))
		Expect(r[0].Value).To(BeNil())
		Expect(r[0].Key).To(Equal(key2))

		By("deleting the entry name1 and expecting an error")
		r, err = c.Delete("name1")
		Expect(err).To(HaveOccurred())
	})
})

func addModifyKVP(key model.Key) *model.KVPair {
	return &model.KVPair{
		Key:      key,
		Value:    uuid.NewV4().String(),
		Revision: uuid.NewV4().String(),
	}
}

func deleteKVP(key model.Key) *model.KVPair {
	return &model.KVPair{
		Key: key,
	}
}
