// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package validator_test

import (
	"github.com/projectcalico/libcalico-go/lib/validator"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

func init() {
	// We need some pointers to ints, so just define as values here.
	var V0 = 0
	var V4 = 4
	var V6 = 6
	var V128 = 128
	var V254 = 254
	var V255 = 255
	var V256 = 256

	// Set up some values we use in various tests.
	ipv4_1 := "1.2.3.4"
	ipv4_2 := "100.200.0.0"
	ipv6_1 :="aabb:aabb::ffff"
	ipv6_2 := "aabb::abcd"
	netv4_1 := "1.2.3.4/32"
	netv4_2 := "1.2.0.0/32"
	netv4_3 := "1.2.3.0/26"
	netv4_4 := "1.2.3.4/10"
	netv4_5 := "1.2.3.4/27"
	netv6_1 := "aabb:aabb::ffff/128"
	netv6_2 := "aabb:aabb::/128"
	netv6_3 := "aabb:aabb::ffff/122"
	netv6_4 := "aabb:aabb::ffff/10"

	protoTCP := numorstring.ProtocolFromString("tcp")
	protoUDP := numorstring.ProtocolFromString("udp")
	protoNumeric := numorstring.ProtocolFromInt(123)

	// badPorts contains a port that should fail validation because it mixes named and numeric
	// ports.
	badPorts := []numorstring.Port{{
		PortName: "foo",
		MinPort:  1,
		MaxPort:  123,
	}}

	// Perform basic validation of different fields and structures to test simple valid/invalid
	// scenarios.  This does not test precise error strings - but does cover a lot of the validation
	// code paths.
	DescribeTable("Validator",
		func(input interface{}, valid bool) {
			if valid {
				Expect(validator.Validate(input)).NotTo(HaveOccurred(),
					"expected value to be valid")
			} else {
				Expect(validator.Validate(input)).To(HaveOccurred(),
					"expected value to be invalid")
			}
		},
		// Empty rule is valid, it means "allow all".
		Entry("empty rule (m)", model.Rule{}, true),

		// (Backend model) Actions.
		Entry("should accept allow action (m)", model.Rule{Action: "allow"}, true),
		Entry("should accept deny action (m)", model.Rule{Action: "deny"}, true),
		Entry("should accept log action (m)", model.Rule{Action: "log"}, true),
		Entry("should reject unknown action (m)", model.Rule{Action: "unknown"}, false),
		Entry("should reject unknown action (m)", model.Rule{Action: "allowfoo"}, false),

		// (API) Actions.
		Entry("should accept allow action", apiv2.Rule{Action: apiv2.Action("Allow")}, true),
		Entry("should accept deny action", apiv2.Rule{Action: apiv2.Action("Deny")}, true),
		Entry("should accept log action", apiv2.Rule{Action: apiv2.Action("Log")}, true),
		Entry("should reject unknown action", apiv2.Rule{Action: "unknown"}, false),
		Entry("should reject unknown action", apiv2.Rule{Action: "allowfoo"}, false),
		Entry("should reject rule with no action", apiv2.Rule{}, false),

		// (Backend model) IP version.
		Entry("should accept IP version 4 (m)", model.Rule{IPVersion: &V4}, true),
		Entry("should accept IP version 6 (m)", model.Rule{IPVersion: &V6}, true),
		Entry("should reject IP version 0 (m)", model.Rule{IPVersion: &V0}, false),

		// (Backend model) Ports.
		Entry("should accept ports with tcp protocol (m)", model.Rule{
			Protocol: &protoTCP,
			SrcPorts: []numorstring.Port{numorstring.SinglePort(80)},
		}, true),
		Entry("should reject src ports with no protocol (m)", model.Rule{
			SrcPorts: []numorstring.Port{numorstring.SinglePort(80)},
		}, false),
		Entry("should reject dst ports with no protocol (m)", model.Rule{
			DstPorts: []numorstring.Port{numorstring.SinglePort(80)},
		}, false),
		Entry("should reject !src ports with no protocol (m)", model.Rule{
			NotSrcPorts: []numorstring.Port{numorstring.SinglePort(80)},
		}, false),
		Entry("should reject !dst ports with no protocol (m)", model.Rule{
			NotDstPorts: []numorstring.Port{numorstring.SinglePort(80)},
		}, false),
		Entry("should accept src named ports with tcp protocol (m)", model.Rule{
			Protocol: &protoTCP,
			SrcPorts: []numorstring.Port{numorstring.NamedPort("foo")},
		}, true),
		Entry("should accept dst named ports with tcp protocol (m)", model.Rule{
			Protocol: &protoTCP,
			DstPorts: []numorstring.Port{numorstring.NamedPort("foo")},
		}, true),
		Entry("should accept !src named ports with tcp protocol (m)", model.Rule{
			Protocol:    &protoTCP,
			NotSrcPorts: []numorstring.Port{numorstring.NamedPort("foo")},
		}, true),
		Entry("should accept !dst named ports with tcp protocol (m)", model.Rule{
			Protocol:    &protoTCP,
			NotDstPorts: []numorstring.Port{numorstring.NamedPort("foo")},
		}, true),
		Entry("should reject src named ports with no protocol (m)", model.Rule{
			SrcPorts: []numorstring.Port{numorstring.NamedPort("foo")},
		}, false),
		Entry("should reject dst named ports with no protocol (m)", model.Rule{
			DstPorts: []numorstring.Port{numorstring.NamedPort("foo")},
		}, false),
		Entry("should reject !src named ports with no protocol (m)", model.Rule{
			NotSrcPorts: []numorstring.Port{numorstring.NamedPort("foo")},
		}, false),
		Entry("should reject !dst named ports with no protocol (m)", model.Rule{
			NotDstPorts: []numorstring.Port{numorstring.NamedPort("foo")},
		}, false),
		// Check that we tell the validator to "dive" and validate the port too.
		Entry("should reject src named ports with min and max (m)", model.Rule{
			Protocol: &protoTCP,
			SrcPorts: badPorts,
		}, false),
		Entry("should reject !src named ports with min and max (m)", model.Rule{
			Protocol:    &protoTCP,
			NotSrcPorts: badPorts,
		}, false),
		Entry("should reject dst named ports with min and max (m)", model.Rule{
			Protocol: &protoTCP,
			DstPorts: badPorts,
		}, false),
		Entry("should reject !dst named ports with min and max (m)", model.Rule{
			Protocol:    &protoTCP,
			NotDstPorts: badPorts,
		}, false),

		// (Backend model) EndpointPorts.
		Entry("should accept EndpointPort with tcp protocol (m)", model.EndpointPort{
			Name:     "a_Jolly-port",
			Protocol: protoTCP,
			Port:     1234,
		}, true),
		Entry("should accept EndpointPort with udp protocol (m)", model.EndpointPort{
			Name:     "a_Jolly-port",
			Protocol: protoUDP,
			Port:     1234,
		}, true),
		Entry("should reject EndpointPort with empty name (m)", model.EndpointPort{
			Name:     "",
			Protocol: protoUDP,
			Port:     1234,
		}, false),
		Entry("should reject EndpointPort with no protocol (m)", model.EndpointPort{
			Name: "a_Jolly-port",
			Port: 1234,
		}, false),
		Entry("should reject EndpointPort with numeric protocol (m)", model.EndpointPort{
			Name:     "a_Jolly-port",
			Protocol: protoNumeric,
			Port:     1234,
		}, false),
		Entry("should reject EndpointPort with no port (m)", model.EndpointPort{
			Name:     "a_Jolly-port",
			Protocol: protoTCP,
		}, false),

		// (API model) EndpointPorts.
		Entry("should accept EndpointPort with tcp protocol", apiv2.EndpointPort{
			Name:     "a_Jolly-port",
			Protocol: protoTCP,
			Port:     1234,
		}, true),
		Entry("should accept EndpointPort with udp protocol", apiv2.EndpointPort{
			Name:     "a_Jolly-port",
			Protocol: protoUDP,
			Port:     1234,
		}, true),
		Entry("should reject EndpointPort with empty name", apiv2.EndpointPort{
			Name:     "",
			Protocol: protoUDP,
			Port:     1234,
		}, false),
		Entry("should reject EndpointPort with no protocol", apiv2.EndpointPort{
			Name: "a_Jolly-port",
			Port: 1234,
		}, false),
		Entry("should reject EndpointPort with numeric protocol", apiv2.EndpointPort{
			Name:     "a_Jolly-port",
			Protocol: protoNumeric,
			Port:     1234,
		}, false),
		Entry("should reject EndpointPort with no port", apiv2.EndpointPort{
			Name:     "a_Jolly-port",
			Protocol: protoTCP,
		}, false),

		// (Backend model) WorkloadEndpoint.
		Entry("should accept WorkloadEndpoint with a port (m)",
			model.WorkloadEndpoint{
				Ports: []model.EndpointPort{
					{
						Name:     "a_Jolly-port",
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			true,
		),
		Entry("should reject WorkloadEndpoint with an unnamed port (m)",
			model.WorkloadEndpoint{
				Ports: []model.EndpointPort{
					{
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			false,
		),
		Entry("should reject WorkloadEndpoint with name-clashing ports (m)",
			model.WorkloadEndpoint{
				Ports: []model.EndpointPort{
					{
						Name:     "a_Jolly-port",
						Protocol: protoTCP,
						Port:     1234,
					},
					{
						Name:     "a_Jolly-port",
						Protocol: protoUDP,
						Port:     5456,
					},
				},
			},
			false,
		),

		// (API) WorkloadEndpointSpec.
		Entry("should accept WorkloadEndpointSpec with a port (m)",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "eth0",
				Ports: []apiv2.EndpointPort{
					{
						Name:     "a_Jolly-port",
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			true,
		),
		Entry("should reject WorkloadEndpointSpec with an unnamed port (m)",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "eth0",
				Ports: []apiv2.EndpointPort{
					{
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			false,
		),
		Entry("should reject WorkloadEndpointSpec with name-clashing ports (m)",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "eth0",
				Ports: []apiv2.EndpointPort{
					{
						Name:     "a_Jolly-port",
						Protocol: protoTCP,
						Port:     1234,
					},
					{
						Name:     "a_Jolly-port",
						Protocol: protoUDP,
						Port:     5456,
					},
				},
			},
			false,
		),

		// (Backend model) HostEndpoint.
		Entry("should accept HostEndpoint with a port (m)",
			model.HostEndpoint{
				Ports: []model.EndpointPort{
					{
						Name:     "a_Jolly-port",
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			true,
		),
		Entry("should reject HostEndpoint with an unnamed port (m)",
			model.HostEndpoint{
				Ports: []model.EndpointPort{
					{
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			false,
		),
		Entry("should reject HostEndpoint with name-clashing ports (m)",
			model.HostEndpoint{
				Ports: []model.EndpointPort{
					{
						Name:     "a_Jolly-port",
						Protocol: protoTCP,
						Port:     1234,
					},
					{
						Name:     "a_Jolly-port",
						Protocol: protoUDP,
						Port:     5456,
					},
				},
			},
			false,
		),

		// (API) HostEndpointSpec.
		Entry("should accept HostEndpointSpec with a port (m)",
			apiv2.HostEndpointSpec{
				InterfaceName: "eth0",
				Ports: []apiv2.EndpointPort{
					{
						Name:     "a_Jolly-port",
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			true,
		),
		Entry("should reject HostEndpointSpec with an unnamed port (m)",
			apiv2.HostEndpointSpec{
				InterfaceName: "eth0",
				Ports: []apiv2.EndpointPort{
					{
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			false,
		),
		Entry("should reject HostEndpointSpec with name-clashing ports (m)",
			apiv2.HostEndpointSpec{
				InterfaceName: "eth0",
				Ports: []apiv2.EndpointPort{
					{
						Name:     "a_Jolly-port",
						Protocol: protoTCP,
						Port:     1234,
					},
					{
						Name:     "a_Jolly-port",
						Protocol: protoUDP,
						Port:     5456,
					},
				},
			},
			false,
		),

		// (API) IP version.
		Entry("should accept IP version 4", apiv2.Rule{Action: apiv2.ActionAllow, IPVersion: &V4}, true),
		Entry("should accept IP version 6", apiv2.Rule{Action: apiv2.ActionAllow, IPVersion: &V6}, true),
		Entry("should reject IP version 0", apiv2.Rule{Action: apiv2.ActionAllow, IPVersion: &V0}, false),

		// (API) Selectors.  Selectors themselves are thorougly UT'd so only need to test simple
		// accept and reject cases here.
		Entry("should accept valid selector", apiv2.EntityRule{Selector: "foo == \"bar\""}, true),
		Entry("should accept valid selector with 'has' and a '/'", apiv2.EntityRule{Selector: "has(calico/k8s_ns)"}, true),
		Entry("should accept valid selector with 'has' and two '/'", apiv2.EntityRule{Selector: "has(calico/k8s_ns/role)"}, true),
		Entry("should accept valid selector with 'has' and two '/' and '-.'", apiv2.EntityRule{Selector: "has(calico/k8s_NS-.1/role)"}, true),
		Entry("should reject invalid selector", apiv2.EntityRule{Selector: "thing=hello &"}, false),

		// (API) Interface.
		Entry("should accept a valid interface", apiv2.WorkloadEndpointSpec{InterfaceName: "ValidIntface0-9"}, true),
		Entry("should reject an interface that is too long", apiv2.WorkloadEndpointSpec{InterfaceName: "interfaceTooLong"}, false),
		Entry("should reject & in an interface", apiv2.WorkloadEndpointSpec{InterfaceName: "Invalid&Intface"}, false),
		Entry("should reject # in an interface", apiv2.WorkloadEndpointSpec{InterfaceName: "Invalid#Intface"}, false),
		Entry("should reject . in an interface", apiv2.WorkloadEndpointSpec{InterfaceName: "Invalid.Intface"}, false),
		Entry("should reject : in an interface", apiv2.WorkloadEndpointSpec{InterfaceName: "Invalid:Intface"}, false),

		// (API) Protocol
		Entry("should accept protocol tcp", protocolFromString("tcp"), true),
		Entry("should accept protocol udp", protocolFromString("udp"), true),
		Entry("should accept protocol icmp", protocolFromString("icmp"), true),
		Entry("should accept protocol icmpv6", protocolFromString("icmpv6"), true),
		Entry("should accept protocol sctp", protocolFromString("sctp"), true),
		Entry("should accept protocol udplite", protocolFromString("udplite"), true),
		Entry("should accept protocol 1 as int", protocolFromInt(1), true),
		Entry("should accept protocol 255 as int", protocolFromInt(255), true),
		Entry("should accept protocol 255 as string", protocolFromString("255"), true),
		Entry("should accept protocol 1 as string", protocolFromString("1"), true),
		Entry("should reject protocol 0 as int", protocolFromInt(0), false),
		Entry("should reject protocol 256 as string", protocolFromString("256"), false),
		Entry("should reject protocol 0 as string", protocolFromString("0"), false),
		Entry("should reject protocol tcpfoo", protocolFromString("tcpfoo"), false),
		Entry("should reject protocol footcp", protocolFromString("footcp"), false),
		Entry("should reject protocol TCP", protocolFromString("TCP"), false),

		// (API) IPNAT
		Entry("should accept valid IPNAT IPv4",
			apiv2.IPNAT{
				InternalIP: ipv4_1,
				ExternalIP: ipv4_2,
			}, true),
		Entry("should accept valid IPNAT IPv6",
			apiv2.IPNAT{
				InternalIP: ipv6_1,
				ExternalIP: ipv6_2,
			}, true),
		Entry("should reject IPNAT mixed IPv4 (int) and IPv6 (ext)",
			apiv2.IPNAT{
				InternalIP: ipv4_1,
				ExternalIP: ipv6_1,
			}, false),
		Entry("should reject IPNAT mixed IPv6 (int) and IPv4 (ext)",
			apiv2.IPNAT{
				InternalIP: ipv6_1,
				ExternalIP: ipv4_1,
			}, false),

		// (API) WorkloadEndpointSpec
		Entry("should accept workload endpoint with interface only",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
			}, true),
		Entry("should accept workload endpoint with networks and no nats",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_1, netv4_2, netv6_1, netv6_2},
			}, true),
		Entry("should accept workload endpoint with IPv4 NAT covered by network",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_1},
				IPNATs:        []apiv2.IPNAT{{InternalIP: ipv4_1, ExternalIP: ipv4_2}},
			}, true),
		Entry("should accept workload endpoint with IPv6 NAT covered by network",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv6_1},
				IPNATs:        []apiv2.IPNAT{{InternalIP: ipv6_1, ExternalIP: ipv6_2}},
			}, true),
		Entry("should accept workload endpoint with IPv4 and IPv6 NAT covered by network",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_1, netv6_1},
				IPNATs: []apiv2.IPNAT{
					{InternalIP: ipv4_1, ExternalIP: ipv4_2},
					{InternalIP: ipv6_1, ExternalIP: ipv6_2},
				},
			}, true),
		Entry("should reject workload endpoint with no config", apiv2.WorkloadEndpointSpec{}, false),
		Entry("should reject workload endpoint with IPv4 networks that contain >1 address",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_3},
			}, false),
		Entry("should reject workload endpoint with IPv6 networks that contain >1 address",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv6_3},
			}, false),
		Entry("should reject workload endpoint with nats and no networks",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNATs:        []apiv2.IPNAT{{InternalIP: ipv4_2, ExternalIP: ipv4_1}},
			}, false),
		Entry("should reject workload endpoint with IPv4 NAT not covered by network",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_1},
				IPNATs:        []apiv2.IPNAT{{InternalIP: ipv4_2, ExternalIP: ipv4_1}},
			}, false),
		Entry("should reject workload endpoint with IPv6 NAT not covered by network",
			apiv2.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv6_1},
				IPNATs:        []apiv2.IPNAT{{InternalIP: ipv6_2, ExternalIP: ipv6_1}},
			}, false),

		// (API) HostEndpointSpec
		Entry("should accept host endpoint with interface",
			apiv2.HostEndpointSpec{
				InterfaceName: "eth0",
			}, true),
		Entry("should accept host endpoint with expected IPs",
			apiv2.HostEndpointSpec{
				ExpectedIPs: []string{ipv4_1, ipv6_1},
			}, true),
		Entry("should accept host endpoint with interface and expected IPs",
			apiv2.HostEndpointSpec{
				InterfaceName: "eth0",
				ExpectedIPs:   []string{ipv4_1, ipv6_1},
			}, true),
		Entry("should reject host endpoint with no config", apiv2.HostEndpointSpec{}, false),
		Entry("should reject host endpoint with blank interface an no IPs",
			apiv2.HostEndpointSpec{
				InterfaceName: "",
				ExpectedIPs:   []string{},
			}, false),

		// (API) PoolMetadata
		Entry("should accept IP pool with IPv4 CIDR /26", apiv2.IPPoolSpec{CIDR: netv4_3}, true),
		Entry("should accept IP pool with IPv4 CIDR /10", apiv2.IPPoolSpec{CIDR: netv4_4}, true),
		Entry("should accept IP pool with IPv6 CIDR /122", apiv2.IPPoolSpec{CIDR: netv6_3}, true),
		Entry("should accept IP pool with IPv6 CIDR /10", apiv2.IPPoolSpec{CIDR: netv6_4}, true),
		Entry("should accept a disabled IP pool with IPv4 CIDR /27",
			apiv2.IPPoolSpec{CIDR: netv4_5, Disabled: true}, true),
		Entry("should accept a disabled IP pool with IPv6 CIDR /128",
			apiv2.IPPoolSpec{CIDR: netv6_1, Disabled: true}, true),
		Entry("should reject IP pool with IPv4 CIDR /27", apiv2.IPPoolSpec{CIDR: netv4_5}, false),
		Entry("should reject IP pool with IPv6 CIDR /128", apiv2.IPPoolSpec{CIDR: netv6_1}, false),
		Entry("should reject IPIP enabled IP pool for IPv6",
			apiv2.IPPoolSpec{
				CIDR: netv6_3,
				IPIP: &apiv2.IPIPConfiguration{Mode: apiv2.IPIPModeAlways},
			}, false),
		Entry("should reject IPv4 pool with a CIDR range overlapping with Link Local range",
			apiv2.IPPoolSpec{CIDR: "169.254.5.0/24"}, false),
		Entry("should reject IPv6 pool with a CIDR range overlapping with Link Local range",
			apiv2.IPPoolSpec{CIDR: "fe80::/120"}, false),

		// (API) IPIPConfiguration
		Entry("should reject IPIP disabled with mode badVal", apiv2.IPIPConfiguration{Mode: apiv2.IPIPMode("badVal")}, false),
		Entry("should accept IPIP enabled with no mode", apiv2.IPIPConfiguration{}, true),
		Entry("should reject IPIP enabled with mode off", apiv2.IPIPConfiguration{Mode: apiv2.IPIPModeOff}, true),
		Entry("should reject IPIP enabled with mode cross-subnet", apiv2.IPIPConfiguration{Mode: apiv2.IPIPModeCrossSubnet}, true),
		Entry("should reject IPIP enabled with mode cross-subnet", apiv2.IPIPConfiguration{Mode: apiv2.IPIPModeAlways}, true),

		// (API) ICMPFields
		Entry("should accept ICMP with no config", apiv2.ICMPFields{}, true),
		Entry("should accept ICMP with type with min value", apiv2.ICMPFields{Type: &V0}, true),
		Entry("should accept ICMP with type with max value", apiv2.ICMPFields{Type: &V254}, true),
		Entry("should accept ICMP with type and code with min value", apiv2.ICMPFields{Type: &V128, Code: &V0}, true),
		Entry("should accept ICMP with type and code with min value", apiv2.ICMPFields{Type: &V128, Code: &V255}, true),
		Entry("should reject ICMP with code and no type", apiv2.ICMPFields{Code: &V0}, false),
		Entry("should reject ICMP with type too high", apiv2.ICMPFields{Type: &V255}, false),
		Entry("should reject ICMP with code too high", apiv2.ICMPFields{Type: &V128, Code: &V256}, false),

		// (API) Rule
		Entry("should accept Rule with protocol sctp and no other config",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("sctp"),
			}, true),
		Entry("should accept Rule with source ports and protocol type 6",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromInt(6),
				Source: apiv2.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, true),
		Entry("should accept Rule with source named ports and protocol type 6",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromInt(6),
				Source: apiv2.EntityRule{
					Ports: []numorstring.Port{numorstring.NamedPort("foo")},
				},
			}, true),
		Entry("should accept Rule with source named ports and protocol type tcp",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Source: apiv2.EntityRule{
					Ports: []numorstring.Port{numorstring.NamedPort("foo")},
				},
			}, true),
		Entry("should accept Rule with source named ports and protocol type udp",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("udp"),
				Source: apiv2.EntityRule{
					Ports: []numorstring.Port{numorstring.NamedPort("foo")},
				},
			}, true),
		Entry("should accept Rule with empty source ports and protocol type 7",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromInt(7),
				Source: apiv2.EntityRule{
					Ports: []numorstring.Port{},
				},
			}, true),
		Entry("should accept Rule with source !ports and protocol type 17",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromInt(17),
				Source: apiv2.EntityRule{
					NotPorts: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, true),
		Entry("should accept Rule with empty source !ports and protocol type 100",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromInt(100),
				Source: apiv2.EntityRule{
					NotPorts: []numorstring.Port{},
				},
			}, true),
		Entry("should accept Rule with dest ports and protocol type tcp",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Destination: apiv2.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, true),
		Entry("should reject Rule with dest ports and no protocol",
			apiv2.Rule{
				Action: "allow",
				Destination: apiv2.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, false),
		Entry("should reject Rule with invalid port (port 0)",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Destination: apiv2.EntityRule{
					NotPorts: []numorstring.Port{numorstring.SinglePort(0)},
				},
			}, false),
		Entry("should reject Rule with invalid port (name + number)",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Destination: apiv2.EntityRule{
					NotPorts: []numorstring.Port{{
						PortName: "foo",
						MinPort:  123,
						MaxPort:  456,
					}},
				},
			}, false),
		Entry("should reject named port Rule with invalid protocol",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("unknown"),
				Destination: apiv2.EntityRule{
					NotPorts: []numorstring.Port{numorstring.NamedPort("foo")},
				},
			}, false),
		Entry("should accept Rule with empty dest ports and protocol type sctp",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("sctp"),
				Destination: apiv2.EntityRule{
					Ports: []numorstring.Port{},
				},
			}, true),
		Entry("should accept Rule with empty dest !ports and protocol type icmpv6",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("icmpv6"),
				Destination: apiv2.EntityRule{
					NotPorts: []numorstring.Port{},
				},
			}, true),
		Entry("should reject Rule with source ports and protocol type 7",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromInt(7),
				Source: apiv2.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, false),
		Entry("should reject Rule with source !ports and protocol type 100",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromInt(100),
				Source: apiv2.EntityRule{
					NotPorts: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, false),
		Entry("should reject Rule with dest ports and protocol type tcp",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("sctp"),
				Destination: apiv2.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, false),
		Entry("should reject Rule with dest !ports and protocol type udp",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("icmp"),
				Destination: apiv2.EntityRule{
					NotPorts: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, false),
		Entry("should reject Rule with invalid source ports and protocol type tcp",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Source: apiv2.EntityRule{
					Ports: []numorstring.Port{{MinPort: 200, MaxPort: 100}},
				},
			}, false),
		Entry("should reject Rule with invalid source !ports and protocol type tcp",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Source: apiv2.EntityRule{
					NotPorts: []numorstring.Port{{MinPort: 200, MaxPort: 100}},
				},
			}, false),
		Entry("should reject Rule with invalid dest ports and protocol type tcp",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Destination: apiv2.EntityRule{
					Ports: []numorstring.Port{{MinPort: 200, MaxPort: 100}},
				},
			}, false),
		Entry("should reject Rule with invalid dest !ports and protocol type tcp",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Destination: apiv2.EntityRule{
					NotPorts: []numorstring.Port{{MinPort: 200, MaxPort: 100}},
				},
			}, false),
		Entry("should reject Rule with one invalid port in the port range (MinPort 0)",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Destination: apiv2.EntityRule{
					NotPorts: []numorstring.Port{{MinPort: 0, MaxPort: 100}},
				},
			}, false),
		Entry("should reject rule mixed IPv4 (src) and IPv6 (dest)",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Source: apiv2.EntityRule{
					Nets: []string{netv4_3},
				},
				Destination: apiv2.EntityRule{
					Nets: []string{netv6_3},
				},
			}, false),
		Entry("should reject rule mixed IPv6 (src) and IPv4 (dest)",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Source: apiv2.EntityRule{
					Nets: []string{netv6_2},
				},
				Destination: apiv2.EntityRule{
					Nets: []string{netv4_2},
				},
			}, false),
		Entry("should reject rule mixed IPv6 version and IPv4 Net",
			apiv2.Rule{
				Action:    "allow",
				Protocol:  protocolFromString("tcp"),
				IPVersion: &V6,
				Source: apiv2.EntityRule{
					Nets: []string{netv4_4},
				},
				Destination: apiv2.EntityRule{
					Nets: []string{netv4_2},
				},
			}, false),
		Entry("should reject rule mixed IPVersion and Source Net IP version",
			apiv2.Rule{
				Action:    "allow",
				Protocol:  protocolFromString("tcp"),
				IPVersion: &V6,
				Source: apiv2.EntityRule{
					Nets: []string{netv4_1},
				},
			}, false),
		Entry("should reject rule mixed IPVersion and Dest Net IP version",
			apiv2.Rule{
				Action:    "allow",
				Protocol:  protocolFromString("tcp"),
				IPVersion: &V4,
				Destination: apiv2.EntityRule{
					Nets: []string{netv6_1},
				},
			}, false),
		Entry("net list: should reject rule mixed IPv4 (src) and IPv6 (dest)",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Source: apiv2.EntityRule{
					Nets: []string{netv4_3},
				},
				Destination: apiv2.EntityRule{
					Nets: []string{netv6_3},
				},
			}, false),
		Entry("net list: should reject rule mixed IPv6 (src) and IPv4 (dest)",
			apiv2.Rule{
				Action:   "allow",
				Protocol: protocolFromString("tcp"),
				Source: apiv2.EntityRule{
					Nets: []string{netv6_2},
				},
				Destination: apiv2.EntityRule{
					Nets: []string{netv4_2},
				},
			}, false),
		Entry("net list: should reject rule mixed IPv6 version and IPv4 Net",
			apiv2.Rule{
				Action:    "allow",
				Protocol:  protocolFromString("tcp"),
				IPVersion: &V6,
				Source: apiv2.EntityRule{
					Nets: []string{netv4_4},
				},
				Destination: apiv2.EntityRule{
					Nets: []string{netv4_2},
				},
			}, false),
		Entry("net list: should reject rule mixed IPv6 version and IPv4 Net",
			apiv2.Rule{
				Action:    "allow",
				Protocol:  protocolFromString("tcp"),
				IPVersion: &V6,
				Source: apiv2.EntityRule{
					Nets: []string{netv4_4},
				},
				Destination: apiv2.EntityRule{
					NotNets: []string{netv4_2},
				},
			}, false),
		Entry("net list: should reject rule mixed IPVersion and Source Net IP version",
			apiv2.Rule{
				Action:    "allow",
				Protocol:  protocolFromString("tcp"),
				IPVersion: &V6,
				Source: apiv2.EntityRule{
					Nets: []string{netv4_1},
				},
			}, false),
		Entry("net list: should reject rule mixed IPVersion and Dest Net IP version",
			apiv2.Rule{
				Action:    "allow",
				Protocol:  protocolFromString("tcp"),
				IPVersion: &V4,
				Destination: apiv2.EntityRule{
					Nets: []string{netv6_1},
				},
			}, false),

		// (API) NodeSpec
		Entry("should accept node with IPv4 BGP", apiv2.NodeSpec{BGP: &apiv2.NodeBGPSpec{IPv4Address: netv4_1}}, true),
		Entry("should accept node with IPv6 BGP", apiv2.NodeSpec{BGP: &apiv2.NodeBGPSpec{IPv6Address: netv6_1}}, true),
		Entry("should accept node with no BGP", apiv2.NodeSpec{}, true),
		Entry("should reject node with BGP but no IPs", apiv2.NodeSpec{BGP: &apiv2.NodeBGPSpec{}}, false),
		Entry("should reject node with IPv6 address in IPv4 field", apiv2.NodeSpec{BGP: &apiv2.NodeBGPSpec{IPv4Address: netv6_1}}, false),
		Entry("should reject node with IPv4 address in IPv6 field", apiv2.NodeSpec{BGP: &apiv2.NodeBGPSpec{IPv6Address: netv4_1}}, false),
		Entry("should reject Policy with both PreDNAT and DoNotTrack",
			apiv2.PolicySpec{
				PreDNAT:    true,
				DoNotTrack: true,
			}, false),
		Entry("should accept Policy with PreDNAT but not DoNotTrack",
			apiv2.PolicySpec{
				PreDNAT: true,
			}, true),
		Entry("should accept Policy with DoNotTrack but not PreDNAT",
			apiv2.PolicySpec{
				PreDNAT:    false,
				DoNotTrack: true,
			}, true),
		Entry("should reject pre-DNAT Policy with egress rules",
			apiv2.PolicySpec{
				PreDNAT:     true,
				EgressRules: []apiv2.Rule{{Action: "allow"}},
			}, false),
		Entry("should accept pre-DNAT Policy with ingress rules",
			apiv2.PolicySpec{
				PreDNAT:      true,
				IngressRules: []apiv2.Rule{{Action: "allow"}},
			}, true),

		// PolicySpec Types field checks.
		Entry("allow missing Types", apiv2.PolicySpec{}, true),
		Entry("allow empty Types", apiv2.PolicySpec{Types: []apiv2.PolicyType{}}, true),
		Entry("allow ingress Types", apiv2.PolicySpec{Types: []apiv2.PolicyType{apiv2.PolicyTypeIngress}}, true),
		Entry("allow egress Types", apiv2.PolicySpec{Types: []apiv2.PolicyType{apiv2.PolicyTypeEgress}}, true),
		Entry("allow ingress+egress Types", apiv2.PolicySpec{Types: []apiv2.PolicyType{apiv2.PolicyTypeIngress, apiv2.PolicyTypeEgress}}, true),
		Entry("disallow repeated egress Types", apiv2.PolicySpec{Types: []apiv2.PolicyType{apiv2.PolicyTypeEgress, apiv2.PolicyTypeEgress}}, false),
		Entry("disallow unexpected value", apiv2.PolicySpec{Types: []apiv2.PolicyType{"unexpected"}}, false),
		Entry("disallow Types without ingress when IngressRules present",
			apiv2.PolicySpec{
				IngressRules: []apiv2.Rule{{Action: "allow"}},
				Types:        []apiv2.PolicyType{apiv2.PolicyTypeEgress},
			}, false),
		Entry("disallow Types without egress when EgressRules present",
			apiv2.PolicySpec{
				EgressRules: []apiv2.Rule{{Action: "allow"}},
				Types:       []apiv2.PolicyType{apiv2.PolicyTypeIngress},
			}, false),
		Entry("allow Types with ingress when IngressRules present",
			apiv2.PolicySpec{
				IngressRules: []apiv2.Rule{{Action: "allow"}},
				Types:        []apiv2.PolicyType{apiv2.PolicyTypeIngress},
			}, true),
		Entry("allow Types with ingress+egress when IngressRules present",
			apiv2.PolicySpec{
				IngressRules: []apiv2.Rule{{Action: "allow"}},
				Types:        []apiv2.PolicyType{apiv2.PolicyTypeIngress, apiv2.PolicyTypeEgress},
			}, true),
		Entry("allow Types with egress when EgressRules present",
			apiv2.PolicySpec{
				EgressRules: []apiv2.Rule{{Action: "allow"}},
				Types:       []apiv2.PolicyType{apiv2.PolicyTypeEgress},
			}, true),
		Entry("allow Types with ingress+egress when EgressRules present",
			apiv2.PolicySpec{
				EgressRules: []apiv2.Rule{{Action: "allow"}},
				Types:       []apiv2.PolicyType{apiv2.PolicyTypeIngress, apiv2.PolicyTypeEgress},
			}, true),
		Entry("allow ingress Types with pre-DNAT",
			apiv2.PolicySpec{
				PreDNAT: true,
				Types:   []apiv2.PolicyType{apiv2.PolicyTypeIngress},
			}, true),
		Entry("disallow egress Types with pre-DNAT",
			apiv2.PolicySpec{
				PreDNAT: true,
				Types:   []apiv2.PolicyType{apiv2.PolicyTypeEgress},
			}, false),
		Entry("disallow ingress+egress Types with pre-DNAT",
			apiv2.PolicySpec{
				PreDNAT: true,
				Types:   []apiv2.PolicyType{apiv2.PolicyTypeIngress, apiv2.PolicyTypeEgress},
			}, false),
	)
}

func protocolFromString(s string) *numorstring.Protocol {
	p := numorstring.ProtocolFromString(s)
	return &p
}

func protocolFromInt(i uint8) *numorstring.Protocol {
	p := numorstring.ProtocolFromInt(i)
	return &p
}
