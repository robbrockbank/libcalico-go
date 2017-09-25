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

package validator

import (
	"net"
	"reflect"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/go-playground/validator.v9"

	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/selector"
	"github.com/projectcalico/libcalico-go/lib/selector/tokenizer"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/apiv2"
)

var validate *validator.Validate

var (
	ipipModeValues = []string{
		string(apiv2.IPIPModeOff),
		string(apiv2.IPIPModeAlways),
		string(apiv2.IPIPModeCrossSubnet),
    }
	actionValues = []string{
		string(apiv2.ActionAllow),
		string(apiv2.ActionDeny),
		string(apiv2.ActionLog),
		string(apiv2.ActionPass),
	}
	policyValues = []string{
		string(apiv2.PolicyTypeIngress),
		string(apiv2.PolicyTypeEgress),
	}
	backendActionValues = []string{
		"allow",
		"deny",
		"log",
		"next-tier",
	}
	protocolValues = []string {
		"TCP",
		"UDP",
		"ICMP",
		"ICMPv6",
		"SCTP",
		"UDPLite",
	}
	labelRegex          = `^` + tokenizer.LabelKeyMatcher + `$`
	labelValueRegex     = "^[a-zA-Z0-9]?([a-zA-Z0-9_.-]{0,61}[a-zA-Z0-9])?$"
	portNameRegex       = "^[a-zA-Z0-9_.-]{1,128}$"
	interfaceRegex      = "^[a-zA-Z0-9_-]{1,15}$"
	reasonString        = "Reason: "
	poolSmallIPv4       = "IP pool size is too small (min /26) for use with Calico IPAM"
	poolSmallIPv6       = "IP pool size is too small (min /122) for use with Calico IPAM"
	poolUnstictCIDR     = "IP pool CIDR is not strictly masked"
	overlapsV4LinkLocal = "IP pool range overlaps with IPv4 Link Local range 169.254.0.0/16"
	overlapsV6LinkLocal = "IP pool range overlaps with IPv6 Link Local range fe80::/10"

	ipv4LinkLocalNet = net.IPNet{
		IP:   net.ParseIP("169.254.0.0"),
		Mask: net.CIDRMask(16, 32),
	}

	ipv6LinkLocalNet = net.IPNet{
		IP:   net.ParseIP("fe80::"),
		Mask: net.CIDRMask(10, 128),
	}
)

// Validate is used to validate the supplied structure according to the
// registered field and structure validators.
func Validate(current interface{}) error {
	err := validate.Struct(current)
	if err == nil {
		return nil
	}

	verr := cerrors.ErrorValidation{}
	for _, f := range err.(validator.ValidationErrors) {
		verr.ErroredFields = append(verr.ErroredFields,
			cerrors.ErroredField{
				Name:   f.Field(),
				StructName: f.StructField(),
				Value:  f.Value(),
				Reason: extractReason(f.Tag()),
			})
	}
	return verr
}

func init() {
	// Initialise static data.
	validate = validator.New()

	// Register field validators.
	registerFieldValidator("action", oneOfValidator(actionValues))
	registerFieldValidator("interface", regexValidator(interfaceRegex))
	registerFieldValidator("backendaction", oneOfValidator(backendActionValues))
	registerFieldValidator("portname", regexValidator(portNameRegex))
	registerFieldValidator("selector", validateSelector)
	registerFieldValidator("labels", validateLabels)
	registerFieldValidator("ipversion", validateIPVersion)
	registerFieldValidator("ipipmode", oneOfValidator(ipipModeValues))
	registerFieldValidator("policytype", oneOfValidator(policyValues))

	// Register struct validators.
	// Shared types.
	registerStructValidator(validateProtocol, numorstring.Protocol{})
	registerStructValidator(validatePort, numorstring.Port{})

	// Frontend API types.
	registerStructValidator(validateIPNAT, apiv2.IPNAT{})
	registerStructValidator(validateWorkloadEndpointSpec, apiv2.WorkloadEndpointSpec{})
	registerStructValidator(validateHostEndpointSpec, apiv2.HostEndpointSpec{})
	registerStructValidator(validateIPPool, apiv2.IPPool{})
	registerStructValidator(validateICMPFields, apiv2.ICMPFields{})
	registerStructValidator(validateRule, apiv2.Rule{})
	registerStructValidator(validateEndpointPort, apiv2.EndpointPort{})
	registerStructValidator(validateNodeSpec, apiv2.NodeSpec{})
	registerStructValidator(validatePolicySpec, apiv2.PolicySpec{})

	// Backend model types.
	registerStructValidator(validateBackendRule, model.Rule{})
	registerStructValidator(validateBackendEndpointPort, model.EndpointPort{})
	registerStructValidator(validateBackendWorkloadEndpoint, model.WorkloadEndpoint{})
	registerStructValidator(validateBackendHostEndpoint, model.HostEndpoint{})
}

// reason returns the provided error reason prefixed with an identifier that
// allows the string to be used as the field tag in the validator and then
// re-extracted as the reason when the validator returns a field error.
func reason(r string) string {
	return reasonString + r
}

// extractReason extracts the error reason from the field tag in a validator
// field error (if there is one).
func extractReason(tag string) string {
	if strings.HasPrefix(tag, reasonString) {
		return strings.TrimPrefix(tag, reasonString)
	}
	return ""
}

func registerFieldValidator(key string, fn validator.Func) {
	validate.RegisterValidation(key, fn)
}

func registerStructValidator(fn validator.StructLevelFunc, t ...interface{}) {
	validate.RegisterStructValidation(fn, t...)
}

func oneOfValidator(values []string) validator.Func {
	reg := "^("+strings.Join(values, "|")+")$"
	return regexValidator(reg)
}

func regexValidator(regex string) validator.Func {
	r := regexp.MustCompile(regex)
	return func(fl validator.FieldLevel) bool {
		s := fl.Field().String()
		log.Debugf("Validate %s: %s", fl.FieldName(), s)
		return r.MatchString(s)
	}
}

func validateIPVersion(fl validator.FieldLevel) bool {
	ver := fl.Field().Int()
	log.Debugf("Validate ip version: %d", ver)
	return ver == 4 || ver == 6
}

func validateSelector(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate selector: %s", s)

	// We use the selector parser to validate a selector string.
	_, err := selector.Parse(s)
	if err != nil {
		log.Debugf("Selector %#v was invalid: %v", s, err)
		return false
	}
	return true
}

func validateLabels(fl validator.FieldLevel) bool {
	//TODO Use Kubernetes function for this
	l := fl.Field().Interface().(map[string]string)
	log.Debugf("Validate labels: %s", l)
	for k, v := range l {
		if !labelRegex.MatchString(k) || !labelValueRegex.MatchString(v) {
			return false
		}
	}
	return true
}

func validateProtocol(sl validator.StructLevel) {
	p := sl.Current().Interface().(numorstring.Protocol)
	log.Debugf("Validate protocol: %v %s %d", p.Type, p.StrVal, p.NumVal)

	// The protocol field may be an integer 1-255 (i.e. not 0), or one of the valid protocol
	// names.
	if num, err := p.NumValue(); err == nil {
		if num == 0 {
			sl.ReportError(reflect.ValueOf(p.NumVal),
				"protocol", "Protocol", reason("protocol number invalid"), "")
		}
	} else if !protocolRegex.MatchString(p.String()) {
		sl.ReportError(reflect.ValueOf(p.String()),
			"protocol", "Protocol", reason("protocol name invalid"), "")
	}
}

func validatePort(sl validator.StructLevel) {
	p := sl.Current().Interface().(numorstring.Port)

	// Check that the port range is in the correct order.  The YAML parsing also checks this,
	// but this protects against misuse of the programmatic API.
	log.Debugf("Validate port: %s")
	if p.MinPort > p.MaxPort {
		sl.ReportError(reflect.ValueOf(p.MaxPort),
			"Port", "port", reason("port range invalid"), "")
	}

	if p.PortName != "" {
		if p.MinPort != 0 || p.MaxPort != 0 {
			sl.ReportError(reflect.ValueOf(p.PortName),
				"Port", "port", reason("named port invalid, if name is specified, min and max should be 0"), "")
		}
	} else if p.MinPort < 1 || p.MaxPort < 1 {
		sl.ReportError(reflect.ValueOf(p.MaxPort),
			"Port", "port", reason("port range invalid, port number must be between 0 and 65536"), "")
	}
}

func validateIPNAT(sl validator.StructLevel) {
	i := sl.Current().Interface().(apiv2.IPNAT)
	log.Debugf("Internal IP: %s; External IP: %s", i.InternalIP, i.ExternalIP)

	ip1 := cnet.MustParseIP(i.InternalIP)
	ip2 := cnet.MustParseIP(i.ExternalIP)
	// An IPNAT must have both the internal and external IP versions the same.
	if ip1.Version() != ip2.Version() {
		sl.ReportError(reflect.ValueOf(i.ExternalIP),
			"ExternalIP", "externalIP", reason("mismatched IP versions"), "")
	}
}

func validateWorkloadEndpointSpec(sl validator.StructLevel) {
	w := sl.Current().Interface().(apiv2.WorkloadEndpointSpec)

	// The configured networks only support /32 (for IPv4) and /128 (for IPv6) at present.
	for _, n := range w.IPNetworks {
		netw := cnet.MustParseNetwork(n)
		ones, bits := netw.Mask.Size()
		if bits != ones {
			sl.ReportError(reflect.ValueOf(w.IPNetworks),
				"IPNetworks", "ipNetworks", reason("IP network contains multiple addresses"), "")
		}
	}

	if len(w.IPv4Gateway) != 0 {
		ip := cnet.MustParseIP(w.IPv4Gateway)
		if ip.Version() != 4 {
			sl.ReportError(reflect.ValueOf(w.IPv4Gateway),
				"IPv4Gateway", "ipv4Gateway", reason("invalid IPv4 gateway address specified"), "")
		}
	}

	if len(w.IPv6Gateway) != 0 {
		ip := cnet.MustParseIP(w.IPv6Gateway)
		if ip.Version() != 6 {
			sl.ReportError(reflect.ValueOf(w.IPv6Gateway),
				"IPv6Gateway", "ipv6Gateway", reason("invalid IPv6 gateway address specified"), "")
		}
	}

	// If NATs have been specified, then they should each be within the configured networks of
	// the endpoint.
	if len(w.IPNATs) > 0 {
		valid := false
		for _, nat := range w.IPNATs {
			// Check each NAT to ensure it is within the configured networks.  If any
			// are not then exit without further checks.
			inat := cnet.MustParseIP(nat.InternalIP)
			valid = false
			for _, n := range w.IPNetworks {
				netw := cnet.MustParseNetwork(n)
				if netw.Contains(inat.IP) {
					valid = true
					break
				}
			}
			if !valid {
				break
			}
		}

		if !valid {
			sl.ReportError(reflect.ValueOf(w.IPNATs),
				"IPNATs", "ipNATs", reason("NAT is not in the endpoint networks"), "")
		}
	}

	// Check for duplicate named ports.
	seenPortNames := map[string]bool{}
	for _, port := range w.Ports {
		if seenPortNames[port.Name] {
			sl.ReportError(
				reflect.ValueOf(port.Name),
				"Ports",
				"",
				reason("Ports list contains duplicate named port."),
				"",
			)
		}
		seenPortNames[port.Name] = true
	}
}

func validateHostEndpointSpec(sl validator.StructLevel) {
	h := sl.Current().Interface().(apiv2.HostEndpointSpec)

	// A host endpoint must have an interface name and/or some expected IPs specified.
	if h.InterfaceName == "" && len(h.ExpectedIPs) == 0 {
		sl.ReportError(reflect.ValueOf(h.InterfaceName),
			"InterfaceName", "interfaceName", reason("no interface or expected IPs have been specified"), "")
	}

	// Check for duplicate named ports.
	seenPortNames := map[string]bool{}
	for _, port := range h.Ports {
		if seenPortNames[port.Name] {
			sl.ReportError(
				reflect.ValueOf(port.Name),
				"Ports",
				"",
				reason("Ports list contains duplicate named port."),
				"",
			)
		}
		seenPortNames[port.Name] = true
	}
}

func validateIPPool(sl validator.StructLevel) {
	pool := sl.Current().Interface().(apiv2.IPPool)

	// The Calico CIDR should be strictly masked
	ip, ipNet, _ := cnet.ParseCIDR(pool.Spec.CIDR)
	log.Debugf("Pool CIDR: %s, Masked IP: %d", pool.Spec.CIDR, ipNet.IP)
	if ipNet.IP.String() != ip.String() {
		sl.ReportError(reflect.ValueOf(pool.Spec.CIDR),
			"CIDR", "cidr", reason(poolUnstictCIDR), "")
	}

	// IPIP cannot be enabled for IPv6.
	if ipNet.Version() == 6 && pool.Spec.IPIP != nil && pool.Spec.IPIP.Mode != apiv2.IPIPModeOff {
		sl.ReportError(reflect.ValueOf(pool.Spec.IPIP.Mode),
			"IPIP.Mode", "IPIP.mode", reason("IPIP is not supported on an IPv6 IP pool"), "")
	}

	// The Calico IPAM places restrictions on the minimum IP pool size.  If
	// the pool is enabled, check that the pool is at least the minimum size.
	if !pool.Spec.Disabled {
		ones, bits := ipNet.Mask.Size()
		log.Debugf("Pool CIDR: %s, num bits: %d", pool.Spec.CIDR, bits-ones)
		if bits-ones < 6 {
			if ipNet.Version() == 4 {
				sl.ReportError(reflect.ValueOf(pool.Spec.CIDR),
					"CIDR", "cidr", reason(poolSmallIPv4), "")
			} else {
				sl.ReportError(reflect.ValueOf(pool.Spec.CIDR),
					"CIDR", "cidr", reason(poolSmallIPv6), "")
			}
		}
	}

	// IP Pool CIDR cannot overlap with IPv4 or IPv6 link local address range.
	if ipNet.Version() == 4 && ipNet.IsNetOverlap(ipv4LinkLocalNet) {
		sl.ReportError(reflect.ValueOf(pool.Spec.CIDR),
			"CIDR", "cidr", reason(overlapsV4LinkLocal), "")
	}

	if ipNet.Version() == 6 && ipNet.IsNetOverlap(ipv6LinkLocalNet) {
		sl.ReportError(reflect.ValueOf(pool.Spec.CIDR),
			"CIDR", "cidr", reason(overlapsV6LinkLocal), "")
	}
}

func validateICMPFields(sl validator.StructLevel) {
	icmp := sl.Current().Interface().(apiv2.ICMPFields)

	// Due to Kernel limitations, ICMP code must always be specified with a type.
	if icmp.Code != nil && icmp.Type == nil {
		sl.ReportError(reflect.ValueOf(icmp.Code),
			"Code", "code", reason("ICMP code specified without an ICMP type"), "")
	}
}

func validateRule(sl validator.StructLevel) {
	rule := sl.Current().Interface().(apiv2.Rule)

	// If the protocol is neither tcp (6) nor udp (17) check that the port values have not
	// been specified.
	if rule.Protocol == nil || !rule.Protocol.SupportsPorts() {
		if len(rule.Source.Ports) > 0 {
			sl.ReportError(reflect.ValueOf(rule.Source.Ports),
				"Source.Ports", "", reason("protocol does not support ports"), "")
		}
		if len(rule.Source.NotPorts) > 0 {
			sl.ReportError(reflect.ValueOf(rule.Source.NotPorts),
				"Source.NotPorts", "", reason("protocol does not support ports"), "")
		}

		if len(rule.Destination.Ports) > 0 {
			sl.ReportError(reflect.ValueOf(rule.Destination.Ports),
				"Destination.Ports", "", reason("protocol does not support ports"), "")
		}
		if len(rule.Destination.NotPorts) > 0 {
			sl.ReportError(reflect.ValueOf(rule.Destination.NotPorts),
				"Destination.NotPorts", "", reason("protocol does not support ports"), "")
		}
	}

	var seenV4, seenV6 bool

	scanNets := func(nets []string, fieldName, structFieldName string) {
		var v4, v6 bool
		for _, net := range nets {
			n := cnet.MustParseNetwork(net)
			v4 = v4 || n.Version() == 4
			v6 = v6 || n.Version() == 6
		}
		if rule.IPVersion != nil && ((v4 && *rule.IPVersion != 4) || (v6 && *rule.IPVersion != 6)) {
			sl.ReportError(reflect.ValueOf(nets), fieldName,
				structFieldName, reason("rule IP version doesn't match CIDR version"), "")
		}
		if v4 && seenV6 || v6 && seenV4 || v4 && v6 {
			// This field makes the rule inconsistent.
			sl.ReportError(reflect.ValueOf(nets), fieldName,
				structFieldName, reason("rule contains both IPv4 and IPv6 CIDRs"), "")
		}
		seenV4 = seenV4 || v4
		seenV6 = seenV6 || v6
	}

	scanNets(rule.Source.Nets, "Source.nets", "Source.Nets")
	scanNets(rule.Source.NotNets, "Source.notNets", "Source.NotNets")
	scanNets(rule.Destination.Nets, "Destination.nets", "Destination.Nets")
	scanNets(rule.Destination.NotNets, "Destination.notNets", "Destination.NotNets")
}

func validateBackendRule(sl validator.StructLevel) {
	rule := sl.Current().Interface().(model.Rule)

	// If the protocol is neither tcp (6) nor udp (17) check that the port values have not
	// been specified.
	if rule.Protocol == nil || !rule.Protocol.SupportsPorts() {
		if len(rule.SrcPorts) > 0 {
			sl.ReportError(reflect.ValueOf(rule.SrcPorts),
				"SrcPorts", "", reason("protocol does not support ports"), "")
		}
		if len(rule.NotSrcPorts) > 0 {
			sl.ReportError(reflect.ValueOf(rule.NotSrcPorts),
				"NotSrcPorts", "", reason("protocol does not support ports"), "")
		}

		if len(rule.DstPorts) > 0 {
			sl.ReportError(reflect.ValueOf(rule.DstPorts),
				"DstPorts", "", reason("protocol does not support ports"), "")
		}
		if len(rule.NotDstPorts) > 0 {
			sl.ReportError(reflect.ValueOf(rule.NotDstPorts),
				"NotDstPorts", "", reason("protocol does not support ports"), "")
		}
	}
}

func validateNodeSpec(sl validator.StructLevel) {
	ns := sl.Current().Interface().(apiv2.NodeSpec)

	if ns.BGP != nil {
		if len(ns.BGP.IPv4Address) == 0 && len(ns.BGP.IPv6Address) == 0 {
			sl.ReportError(reflect.ValueOf(ns.BGP.IPv4Address),
				"BGP.IPv4Address", "", reason("no BGP IP address and subnet specified"), "")
		}
	}
}

func validateBackendEndpointPort(sl validator.StructLevel) {
	port := sl.Current().Interface().(model.EndpointPort)

	if port.Protocol.String() != "tcp" && port.Protocol.String() != "udp" {
		sl.ReportError(
			reflect.ValueOf(port.Protocol),
			"EndpointPort.Protocol",
			"",
			reason("EndpointPort protocol must be 'tcp' or 'udp'."),
			"",
		)
	}
}

func validateEndpointPort(sl validator.StructLevel) {
	port := sl.Current().Interface().(apiv2.EndpointPort)

	if port.Protocol.String() != "tcp" && port.Protocol.String() != "udp" {
		sl.ReportError(
			reflect.ValueOf(port.Protocol),
			"EndpointPort.Protocol",
			"",
			reason("EndpointPort protocol must be 'tcp' or 'udp'."),
			"",
		)
	}
}

func validateBackendWorkloadEndpoint(sl validator.StructLevel) {
	ep := sl.Current().Interface().(model.WorkloadEndpoint)

	seenPortNames := map[string]bool{}
	for _, port := range ep.Ports {
		if seenPortNames[port.Name] {
			sl.ReportError(
				reflect.ValueOf(port.Name),
				"WorkloadEndpoint.Ports",
				"",
				reason("Ports list contains duplicate named port."),
				"",
			)
		}
		seenPortNames[port.Name] = true
	}
}

func validateBackendHostEndpoint(sl validator.StructLevel) {
	ep := sl.Current().Interface().(model.HostEndpoint)

	seenPortNames := map[string]bool{}
	for _, port := range ep.Ports {
		if seenPortNames[port.Name] {
			sl.ReportError(
				reflect.ValueOf(port.Name),
				"HostEndpoint.Ports",
				"",
				reason("Ports list contains duplicate named port."),
				"",
			)
		}
		seenPortNames[port.Name] = true
	}
}

func validatePolicySpec(sl validator.StructLevel) {
	m := sl.Current().Interface().(apiv2.PolicySpec)

	if m.DoNotTrack && m.PreDNAT {
		sl.ReportError(reflect.ValueOf(m.PreDNAT),
			"PolicySpec.PreDNAT", "", reason("PreDNAT and DoNotTrack cannot both be true, for a given PolicySpec"), "")
	}

	if m.PreDNAT && len(m.EgressRules) > 0 {
		sl.ReportError(reflect.ValueOf(m.EgressRules),
			"PolicySpec.EgressRules", "", reason("PreDNAT PolicySpec cannot have any EgressRules"), "")
	}

	if m.PreDNAT && len(m.Types) > 0 {
		for _, t := range m.Types {
			if t == apiv2.PolicyTypeEgress {
				sl.ReportError(reflect.ValueOf(m.Types),
					"PolicySpec.Types", "", reason("PreDNAT PolicySpec cannot have 'egress' Type"), "")
			}
		}
	}

	// Check (and disallow) any repeats in Types field.
	mp := map[apiv2.PolicyType]bool{}
	for _, t := range m.Types {
		if _, exists := mp[t]; exists {
			sl.ReportError(reflect.ValueOf(m.Types),
				"PolicySpec.Types", "", reason("'"+string(t)+"' type specified more than once"), "")
		} else {
			mp[t] = true
		}
	}

	// When Types is explicitly specified:
	if len(m.Types) > 0 {
		var exists bool
		// 'ingress' type must be there if Policy has any ingress rules.
		_, exists = mp[apiv2.PolicyTypeIngress]
		if len(m.IngressRules) > 0 && !exists {
			sl.ReportError(reflect.ValueOf(m.Types),
				"PolicySpec.Types", "", reason("'ingress' must be specified when policy has ingress rules"), "")
		}
		// 'egress' type must be there if Policy has any egress rules.
		_, exists = mp[apiv2.PolicyTypeEgress]
		if len(m.EgressRules) > 0 && !exists {
			sl.ReportError(reflect.ValueOf(m.Types),
				"PolicySpec.Types", "", reason("'egress' must be specified when policy has egress rules"), "")
		}
	}
}
