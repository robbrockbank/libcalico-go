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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
)

var (

	// Definitions to make the test code more readable
	isGlobalConfig = true
	isNodeConfig   = false
)

var _ = Describe("Test the backend datstore multi-watch syncer", func() {
	// Define some common values
	perNodeFelixKey := model.ResourceKey{
		Kind: apiv2.KindFelixConfiguration,
		Name: "node.mynode",
	}
	globalFelixKey := model.ResourceKey{
		Kind: apiv2.KindFelixConfiguration,
		Name: "default",
	}
	invalidFelixKey := model.ResourceKey{
		Kind: apiv2.KindFelixConfiguration,
		Name: "foobar",
	}
	globalClusterKey := model.ResourceKey{
		Kind: apiv2.KindClusterInformation,
		Name: "default",
	}
	nodeClusterKey := model.ResourceKey{
		Kind: apiv2.KindClusterInformation,
		Name: "node.mynode",
	}
	numFelixConfigs   := 46
	numClusterConfigs := 3
	felixMappedNames  := map[string]interface{}{
		"RouteRefreshInterval": nil,
		"IptablesRefreshInterval": nil,
		"IpsetsRefreshInterval": nil,
	}

	It("should handle conversion of node-specific delete with no additional configs", func() {
		cc := updateprocessors.NewFelixConfigUpdateProcessor()
		By("converting a per-node felix key and checking for the correct number of fields")
		kvps, err := cc.Process(&model.KVPair{
			Key: perNodeFelixKey,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(kvps, isNodeConfig, numFelixConfigs, felixMappedNames)
	})

	It("should handle conversion of global delete with no additional configs", func() {
		cc := updateprocessors.NewFelixConfigUpdateProcessor()
		By("converting a global felix key and checking for the correct number of fields")
		kvps, err := cc.Process(&model.KVPair{
			Key: globalFelixKey,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(kvps, isGlobalConfig, numFelixConfigs, felixMappedNames)
	})

	It("should handle conversion of node-specific zero value KVPairs with no additional configs", func() {
		cc := updateprocessors.NewFelixConfigUpdateProcessor()
		kvps, err := cc.Process(&model.KVPair{
			Key:   perNodeFelixKey,
			Value: apiv2.NewFelixConfiguration(),
		})
		Expect(err).NotTo(HaveOccurred())
		// Explicitly pass in the "mapped" name values to check to ensure the names are mapped.
		checkExpectedConfigs(
			kvps,
			isNodeConfig,
			numFelixConfigs,
			felixMappedNames,
		)
	})

	It("should handle conversion of global zero value KVPairs with no additional configs", func() {
		cc := updateprocessors.NewFelixConfigUpdateProcessor()
		kvps, err := cc.Process(&model.KVPair{
			Key:   globalFelixKey,
			Value: apiv2.NewFelixConfiguration(),
		})
		Expect(err).NotTo(HaveOccurred())
		// Explicitly pass in the "mapped" name values to check to ensure the names are mapped.
		checkExpectedConfigs(
			kvps,
			isGlobalConfig,
			numFelixConfigs,
			felixMappedNames,
		)
	})

	It("should gracefully handle invalid names/keys/types/values", func() {
		cc := updateprocessors.NewFelixConfigUpdateProcessor()
		By("Testing invalid Key on ProcessDeleted")
		_, err := cc.Process(&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: net.MustParseIP("1.2.3.4"),
			},
		})
		Expect(err).To(HaveOccurred())

		By("Testing invalid Key on Process")
		_, err = cc.Process(&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: net.MustParseIP("1.2.3.4"),
			},
			Value: apiv2.NewFelixConfiguration(),
		})
		Expect(err).To(HaveOccurred())

		By("Testing non-resource type value on Process with add/mod")
		_, err = cc.Process(&model.KVPair{
			Key:   globalFelixKey,
			Value: "this isn't a resource",
		})
		Expect(err).To(HaveOccurred())

		By("Testing incorrect resource type value on Process with add/mod")
		_, err = cc.Process(&model.KVPair{
			Key:   globalFelixKey,
			Value: apiv2.NewWorkloadEndpoint(),
		})
		Expect(err).To(HaveOccurred())

		By("Testing incorrect name structure on Process with add/mod")
		_, err = cc.Process(&model.KVPair{
			Key:   invalidFelixKey,
			Value: apiv2.NewFelixConfiguration(),
		})
		Expect(err).To(HaveOccurred())

		By("Testing incorrect name structure on Process with delete")
		_, err = cc.Process(&model.KVPair{
			Key: invalidFelixKey,
		})
		Expect(err).To(HaveOccurred())
	})

	It("should handle different field types being assigned", func() {
		cc := updateprocessors.NewFelixConfigUpdateProcessor()
		By("converting a per-node felix KVPair with certain values and checking for the correct number of fields")
		res := apiv2.NewFelixConfiguration()
		int1 := int(12345)
		bool1 := false
		uint1 := uint32(1313)
		res.Spec.RouteRefreshIntervalSecs = &int1
		res.Spec.InterfacePrefix = "califoobar"
		res.Spec.IpInIpEnabled = &bool1
		res.Spec.IptablesMarkMask = &uint1
		res.Spec.FailsafeInboundHostPorts = &[]apiv2.ProtoPort{}
		res.Spec.FailsafeOutboundHostPorts = &[]apiv2.ProtoPort{
			{
				Protocol: "tcp",
				Port:     1234,
			},
			{
				Protocol: "udp",
				Port:     22,
			},
			{
				Protocol: "tcp",
				Port:     65535,
			},
		}
		expected := map[string]interface{}{
			"RouteRefreshInterval":      "12345",
			"InterfacePrefix":           "califoobar",
			"IpInIpEnabled":             "false",
			"IptablesMarkMask":          "1313",
			"FailsafeInboundHostPorts":  "",
			"FailsafeOutboundHostPorts": "tcp:1234,udp:22,tcp:65535",
		}
		kvps, err := cc.Process(&model.KVPair{
			Key:   perNodeFelixKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeConfig,
			numFelixConfigs,
			expected,
		)
	})

	It("should handle cluster config string slice field", func() {
		cc := updateprocessors.NewClusterInfoUpdateProcessor()
		By("converting a global cluster info KVPair with values assigned")
		res := apiv2.NewClusterInformation()
		res.Spec.ClusterGUID = "abcedfg"
		res.Spec.ClusterType = []string{
			"Mesos",
			"K8s",
		}
		expected := map[string]interface{}{
			"ClusterGUID": "abcedfg",
			"ClusterType": "Mesos,K8s",
		}
		kvps, err := cc.Process(&model.KVPair{
			Key:   globalClusterKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isGlobalConfig,
			numClusterConfigs,
			expected,
		)
	})

	It("should allow setting of a known field through an annotation to override validation", func() {
		cc := updateprocessors.NewClusterInfoUpdateProcessor()
		res := apiv2.NewClusterInformation()
		res.Annotations = map[string]string{
			"config.projectcalico.org/ClusterType": "this is not validated!",
		}
		expected := map[string]interface{}{
			"ClusterType": "this is not validated!",
		}
		kvps, err := cc.Process(&model.KVPair{
			Key:   globalClusterKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isGlobalConfig,
			numClusterConfigs,
			expected,
		)
	})

	It("should override struct value when equivalent annotation is set", func() {
		cc := updateprocessors.NewClusterInfoUpdateProcessor()
		res := apiv2.NewClusterInformation()
		res.Annotations = map[string]string{
			"config.projectcalico.org/ClusterType":   "this is not validated!",
			"config.projectcalico.org/CalicoVersion": "version foobar",
		}
		res.Spec.ClusterType = []string{
			"Mesos",
			"K8s",
		}
		res.Spec.CalicoVersion = "calicov1"
		expected := map[string]interface{}{
			"ClusterType":   "this is not validated!",
			"CalicoVersion": "version foobar",
		}
		kvps, err := cc.Process(&model.KVPair{
			Key:   nodeClusterKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeConfig,
			numClusterConfigs,
			expected,
		)
	})

	It("should handle new config options specified through annotations", func() {
		cc := updateprocessors.NewClusterInfoUpdateProcessor()
		res := apiv2.NewClusterInformation()

		By("validating that the new values are output in addition to the existing ones")
		res.Annotations = map[string]string{
			"config.projectcalico.org/NewConfigType":        "newFieldValue",
			"config.projectcalico.org/AnotherNewConfigType": "newFieldValue2",
			"thisisnotvalid":                                "not included",
		}
		res.Spec.ClusterType = []string{
			"Mesos",
			"K8s",
		}
		expected := map[string]interface{}{
			"ClusterType":          "Mesos,K8s",
			"NewConfigType":        "newFieldValue",
			"AnotherNewConfigType": "newFieldValue2",
		}
		kvps, err := cc.Process(&model.KVPair{
			Key:   globalClusterKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isGlobalConfig,
			numClusterConfigs+2,
			expected,
		)

		By("validating that the options are persisted to allow delete notifications")
		res.Annotations = nil
		expected = map[string]interface{}{
			"ClusterType":          "Mesos,K8s",
			"NewConfigType":        nil,
			"AnotherNewConfigType": nil,
		}
		kvps, err = cc.Process(&model.KVPair{
			Key:   globalClusterKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isGlobalConfig,
			numClusterConfigs+2,
			expected,
		)

		By("validating the delete keys also include the cached config options")
		kvps, err = cc.Process(&model.KVPair{
			Key: globalClusterKey,
		})
		checkExpectedConfigs(
			kvps,
			isGlobalConfig,
			numClusterConfigs+2,
			map[string]interface{}{
				"NewConfigType": nil,
				"AnotherNewConfigType": nil,
			},
		)

		By("adding another new config option and reusing one of the previous ones")
		res.Annotations = map[string]string{
			"config.projectcalico.org/NewConfigType":           "foobar",
			"config.projectcalico.org/YetAnotherNewConfigType": "foobarbaz",
		}
		res.Spec.ClusterType = nil
		expected = map[string]interface{}{
			"ClusterType":             "",
			"NewConfigType":           "foobar",
			"AnotherNewConfigType":    nil,
			"YetAnotherNewConfigType": "foobarbaz",
		}
		kvps, err = cc.Process(&model.KVPair{
			Key:   globalClusterKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isGlobalConfig,
			numClusterConfigs+3,
			expected,
		)

		By("validating the delete keys also include the new cached config option")
		kvps, err = cc.Process(&model.KVPair{
			Key: globalClusterKey,
		})
		checkExpectedConfigs(
			kvps,
			isGlobalConfig,
			numClusterConfigs+3,
			map[string]interface{}{
				"NewConfigType": nil,
				"AnotherNewConfigType": nil,
				"YetAnotherNewConfigType": nil,
			},
		)

		By("invoking resync and checking old fields are no longer cached")
		cc.SyncStarting()
		res.Annotations = nil
		res.Spec.ClusterType = nil
		kvps, err = cc.Process(&model.KVPair{
			Key:   globalClusterKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		expected = map[string]interface{}{
			"ClusterType": "",
		}
		checkExpectedConfigs(
			kvps,
			isGlobalConfig,
			numClusterConfigs,
			expected,
		)

		By("validating the delete keys are also back to original")
		kvps, err = cc.Process(&model.KVPair{
			Key: globalClusterKey,
		})
		checkExpectedConfigs(
			kvps,
			isGlobalConfig,
			numClusterConfigs,
			nil,
		)
	})
})

// Check the KVPairs returned by the UpdateProcessor are as expected.  The expectedValues contains
// the expected set of data in the updates, any config not specified in the set is expected
// to be nil in the KVPair.
// You can use expectedValues to verify certain fields were included in the response even
// if the values were nil.
func checkExpectedConfigs(kvps []*model.KVPair, isGlobal bool, expectedNum int, expectedValues map[string]interface{}) {
	// Copy/convert input data.  We keep track of:
	// - all field names, so that we can check for duplicates
	// - extra fields that we have not yet seen
	// - expected field values that we have not yet validated
	ev := make(map[string]interface{}, len(expectedValues))
	for k, v := range expectedValues {
		ev[k] = v
	}
	allNames := map[string]struct{}{}

	By("checking the expected number of results")
	Expect(kvps).To(HaveLen(expectedNum))

	By("checking for duplicated, nil values and assigned values as expected")
	for _, kvp := range kvps {
		var name string
		if isGlobal {
			Expect(kvp.Key).To(BeAssignableToTypeOf(model.GlobalConfigKey{}))
			name = kvp.Key.(model.GlobalConfigKey).Name
		} else {
			Expect(kvp.Key).To(BeAssignableToTypeOf(model.HostConfigKey{}))
			node := kvp.Key.(model.HostConfigKey).Hostname
			Expect(node).To(Equal("mynode"))
			name = kvp.Key.(model.HostConfigKey).Name
		}

		// Validate and track the expected values.
		if v, ok := ev[name]; ok {
			if v == nil {
				Expect(kvp.Value).To(BeNil(), "Field: "+name)
			} else {
				Expect(kvp.Value).To(Equal(v), "Field: "+name)
			}
			delete(ev, name)
		} else {
			Expect(kvp.Value).To(BeNil(), "Field: "+name)
		}

		// Validate the fields we have seen, checking for duplicates.
		_, ok := allNames[name]
		Expect(ok).To(BeFalse(), fmt.Sprintf("config name is repeated in response: %s", name))
		allNames[name] = struct{}{}
	}

	By("checking all expected values were accounted for")
	Expect(ev).To(HaveLen(0), fmt.Sprintf("config name missing in response"))
}
