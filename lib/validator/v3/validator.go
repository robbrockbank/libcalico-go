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

package v3

import (
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/go-playground/validator.v9"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/selector"
)

// Define a validate that has our registered validation functions.
var validate *validator.Validate

// Maximum size of annotations.
const totalAnnotationSizeLimitB int64 = 256 * (1 << 10) // 256 kB`

var (
	nameLabelFmt     = "[a-z0-9]([-a-z0-9]*[a-z0-9])?"
	nameSubdomainFmt = nameLabelFmt + "(\\." + nameLabelFmt + ")*"

	// All resource names must follow the subdomain name format.  Some resources we impose
	// more restrictive naming requirements.
	nameRegex = regexp.MustCompile("^" + nameSubdomainFmt + "$")

	// NetworkPolicy names must either be a simple DNS1123 label format (nameLabelFmt), or
	// must be the standard name format (nameRegex) prefixed with "knp.default".
	networkPolicyNameRegex = regexp.MustCompile("^((" + nameLabelFmt + ")|(knp\\.default\\.(" + nameSubdomainFmt + ")))$")

	// GlobalNetworkPolicy names must either be a simple DNS1123 label format (nameLabelFmt).
	globalNetworkPolicyNameRegex = regexp.MustCompile("^(" + nameLabelFmt + ")$")

	interfaceRegex        = regexp.MustCompile("^[a-zA-Z0-9_-]{1,15}$")
	actionRegex           = regexp.MustCompile("^(Allow|Deny|Log|Pass)$")
	protocolRegex         = regexp.MustCompile("^(TCP|UDP|ICMP|ICMPv6|SCTP|UDPLite)$")
	ipipModeRegex         = regexp.MustCompile("^(Always|CrossSubnet|Never)$")
	logLevelRegex         = regexp.MustCompile("^(Debug|Info|Warning|Error|Fatal)$")
	datastoreType         = regexp.MustCompile("^(etcdv3|kubernetes)$")
	dropAcceptReturnRegex = regexp.MustCompile("^(Drop|Accept|Return)$")
	acceptReturnRegex     = regexp.MustCompile("^(Accept|Return)$")
	reasonString          = "Reason: "
	poolSmallIPv4         = "IP pool size is too small (min /26) for use with Calico IPAM"
	poolSmallIPv6         = "IP pool size is too small (min /122) for use with Calico IPAM"
	poolUnstictCIDR       = "IP pool CIDR is not strictly masked"
	overlapsV4LinkLocal   = "IP pool range overlaps with IPv4 Link Local range 169.254.0.0/16"
	overlapsV6LinkLocal   = "IP pool range overlaps with IPv6 Link Local range fe80::/10"
	protocolPortsMsg      = "rules that specify ports must set protocol to TCP or UDP"

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
	// Perform field-only validation first, that way the struct validators can assume
	// individual fields are valid format.
	if err := validate.Struct(current); err != nil {
		return convertError(err)
	}
	return nil
}

func convertError(err error) errors.ErrorValidation {
	verr := errors.ErrorValidation{}
	for _, f := range err.(validator.ValidationErrors) {
		verr.ErroredFields = append(verr.ErroredFields,
			errors.ErroredField{
				Name:   f.Namespace(),
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
	validate.RegisterValidation("action", validateAction)
	validate.RegisterValidation("interface", validateInterface)
	validate.RegisterValidation("datastoreType", validateDatastoreType)
	validate.RegisterValidation("name", validateName)
	validate.RegisterValidation("selector", validateSelector)
	validate.RegisterValidation("labels", validateLabels)
	validate.RegisterValidation("ipVersion", validateIPVersion)
	validate.RegisterValidation("ipIpMode", validateIPIPMode)
	validate.RegisterValidation("policyType", validatePolicyType)
	validate.RegisterValidation("logLevel", validateLogLevel)
	validate.RegisterValidation("dropAcceptReturn", validateFelixEtoHAction)
	validate.RegisterValidation("acceptReturn", validateAcceptReturn)
	validate.RegisterValidation("portName", validatePortName)

	// Register network validators (i.e. validating a correctly masked CIDR).  Also
	// accepts an IP address without a mask (assumes a full mask).
	validate.RegisterValidation("netv4", validateIPv4Network)
	validate.RegisterValidation("netv6", validateIPv6Network)
	validate.RegisterValidation("net", validateIPNetwork)

	// Override the default CIDR validate.  Validates an arbitrary CIDR (does not
	// need to be correctly masked).  Also accepts an IP address without a mask.
	validate.RegisterValidation("cidrv4", validateCIDRv4)
	validate.RegisterValidation("cidrv6", validateCIDRv6)
	validate.RegisterValidation("cidr", validateCIDR)

	// Register structs that have no additional sub structs for first round of validation.
	validate.RegisterStructValidation(validateProtocol, numorstring.Protocol{})
	validate.RegisterStructValidation(validateProtoPort, api.ProtoPort{})
	validate.RegisterStructValidation(validatePort, numorstring.Port{})
	validate.RegisterStructValidation(validateEndpointPort, api.EndpointPort{})
	validate.RegisterStructValidation(validateIPNAT, api.IPNAT{})
	validate.RegisterStructValidation(validateICMPFields, api.ICMPFields{})
	validate.RegisterStructValidation(validateIPPoolSpec, api.IPPoolSpec{})
	validate.RegisterStructValidation(validateNodeSpec, api.NodeSpec{})
	validate.RegisterStructValidation(validateObjectMeta, metav1.ObjectMeta{})

	// Register structs that have one level of additional structs to validate.
	validate.RegisterStructValidation(validateWorkloadEndpointSpec, api.WorkloadEndpointSpec{})
	validate.RegisterStructValidation(validateHostEndpointSpec, api.HostEndpointSpec{})
	validate.RegisterStructValidation(validateRule, api.Rule{})

	// Register structs that have two level of additional structs to validate.
	validate.RegisterStructValidation(validateNetworkPolicy, api.NetworkPolicy{})
	validate.RegisterStructValidation(validateGlobalNetworkPolicy, api.GlobalNetworkPolicy{})
}

// reason returns the provided error reason prefixed with an identifier that
// allows the string to be used as the field tag in the validate and then
// re-extracted as the reason when the validate returns a field error.
func reason(r string) string {
	return reasonString + r
}

// extractReason extracts the error reason from the field tag in a validate
// field error (if there is one).
func extractReason(tag string) string {
	if strings.HasPrefix(tag, reasonString) {
		return strings.TrimPrefix(tag, reasonString)
	}
	return ""
}

func validateAction(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate action: %s", s)
	return actionRegex.MatchString(s)
}

func validateInterface(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate interface: %s", s)
	return interfaceRegex.MatchString(s)
}

func validateDatastoreType(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate Datastore Type: %s", s)
	return datastoreType.MatchString(s)
}

func validateName(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate name: %s", s)
	return nameRegex.MatchString(s)
}

func validatePortName(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate port name: %s", s)
	return len(s) != 0 && len(k8svalidation.IsValidPortName(s)) == 0
}

func validateIPVersion(fl validator.FieldLevel) bool {
	ver := fl.Field().Int()
	log.Debugf("Validate ip version: %d", ver)
	return ver == 4 || ver == 6
}

func validateIPIPMode(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate IPIP Mode: %s", s)
	return ipipModeRegex.MatchString(s)
}

func validateLogLevel(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate Felix log level: %s", s)
	return logLevelRegex.MatchString(s)
}

func validateFelixEtoHAction(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate Felix DefaultEndpointToHostAction: %s", s)
	return dropAcceptReturnRegex.MatchString(s)
}

func validateAcceptReturn(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate Accept Return Action: %s", s)
	return acceptReturnRegex.MatchString(s)
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
	labels := fl.Field().Interface().(map[string]string)
	for k, v := range labels {
		if len(k8svalidation.IsQualifiedName(k)) != 0 {
			return false
		}
		if len(k8svalidation.IsValidLabelValue(v)) != 0 {
			return false
		}
	}
	return true
}

func validatePolicyType(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate policy type: %s", s)
	if s == string(api.PolicyTypeIngress) || s == string(api.PolicyTypeEgress) {
		return true
	}
	return false
}

// validateIPv4Network validates the field is a valid (strictly masked) IPv4 network.
// An IP address is valid, and assumed to be fully masked (i.e /32)
func validateIPv4Network(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IPv4 network: %s", n)
	ipa, ipn, err := cnet.ParseCIDROrIP(n)
	if err != nil {
		return false
	}

	// Check for the correct version and that the CIDR is correctly masked (by comparing the
	// parsed IP against the IP in the parsed network).
	return ipa.Version() == 4 && ipn.IP.String() == ipa.String()
}

// validateIPv4Network validates the field is a valid (strictly masked) IPv6 network.
// An IP address is valid, and assumed to be fully masked (i.e /128)
func validateIPv6Network(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IPv6 network: %s", n)
	ipa, ipn, err := cnet.ParseCIDROrIP(n)
	if err != nil {
		return false
	}

	// Check for the correct version and that the CIDR is correctly masked (by comparing the
	// parsed IP against the IP in the parsed network).
	return ipa.Version() == 6 && ipn.IP.String() == ipa.String()
}

// validateIPv4Network validates the field is a valid (strictly masked) IP network.
// An IP address is valid, and assumed to be fully masked (i.e /32 or /128)
func validateIPNetwork(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IP network: %s", n)
	ipa, ipn, err := cnet.ParseCIDROrIP(n)
	if err != nil {
		return false
	}

	// Check  that the CIDR is correctly masked (by comparing the parsed IP against
	// the IP in the parsed network).
	return ipn.IP.String() == ipa.String()
}

// validateIPv4Network validates the field is a valid (not strictly masked) IPv4 network.
// An IP address is valid, and assumed to be fully masked (i.e /32)
func validateCIDRv4(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IPv4 network: %s", n)
	ipa, _, err := cnet.ParseCIDROrIP(n)
	if err != nil {
		return false
	}

	return ipa.Version() == 4
}

// validateIPv4Network validates the field is a valid (not strictly masked) IPv6 network.
// An IP address is valid, and assumed to be fully masked (i.e /128)
func validateCIDRv6(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IPv6 network: %s", n)
	ipa, _, err := cnet.ParseCIDROrIP(n)
	if err != nil {
		return false
	}

	return ipa.Version() == 6
}

// validateIPv4Network validates the field is a valid (not strictly masked) IP network.
// An IP address is valid, and assumed to be fully masked (i.e /32 or /128)
func validateCIDR(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IP network: %s", n)
	_, _, err := cnet.ParseCIDROrIP(n)
	return err == nil
}

func validatePort(sl validator.StructLevel) {
	p := sl.Current().Interface().(numorstring.Port)

	// Check that the port range is in the correct order.  The YAML parsing also checks this,
	// but this protects against misuse of the programmatic API.
	log.Debugf("Validate port: %v", p)
	if p.MinPort > p.MaxPort {
		sl.ReportError(
			p.MinPort,
			"",
			"MinPort",
			"minGtMaxPort",
			p.MinPort,
		)
	}

	if p.PortName != "" {
		if p.MinPort != 0 || p.MaxPort != 0 {
			sl.ReportError(
				reflect.ValueOf(p.PortName),
				"",
				"PortName",
				"port",
				reason("named port invalid, if name is specified, min and max should be 0"),
			)
		}
	} else if p.MinPort < 1 || p.MaxPort < 1 {
		sl.ReportError(
			reflect.ValueOf(p.MaxPort),
			"Port",
			"",
			reason("port range invalid, port number must be between 0 and 65536"),
		)
	}
}

func validateIPNAT(sl validator.StructLevel) {
	i := sl.Current().Interface().(api.IPNAT)
	log.Debugf("Internal IP: %s; External IP: %s", i.InternalIP, i.ExternalIP)

	iip, _, err := cnet.ParseCIDROrIP(i.InternalIP)
	if err != nil {
		sl.ReportError(
			reflect.ValueOf(i.ExternalIP),
			"InternalIP",
			"",
			reason("invalid IP address"),
		)
	}

	eip, _, err := cnet.ParseCIDROrIP(i.ExternalIP)
	if err != nil {
		sl.ReportError(
			reflect.ValueOf(i.ExternalIP),
			"InternalIP",
			"",
			reason("invalid IP address"),
		)
	}

	// An IPNAT must have both the internal and external IP versions the same.
	if iip.Version() != eip.Version() {
		sl.ReportError(
			reflect.ValueOf(i.ExternalIP),
			"ExternalIP",
			"",
			reason("mismatched IP versions"),
		)
	}
}

func validateWorkloadEndpointSpec(sl validator.StructLevel) {
	w := sl.Current().Interface().(api.WorkloadEndpointSpec)

	// The configured networks only support /32 (for IPv4) and /128 (for IPv6) at present.
	for _, netw := range w.IPNetworks {
		_, nw, err := cnet.ParseCIDROrIP(netw)
		if err != nil {
			sl.ReportError(reflect.ValueOf(netw),
				"IPNetworks", "", reason("invalid CIDR"))
		}

		ones, bits := nw.Mask.Size()
		if bits != ones {
			sl.ReportError(reflect.ValueOf(w.IPNetworks),
				"IPNetworks", "", reason("IP network contains multiple addresses"))
		}
	}

	_, v4gw, err := cnet.ParseCIDROrIP(w.IPv4Gateway)
	if err != nil {
		sl.ReportError(reflect.ValueOf(w.IPv4Gateway),
			"IPv4Gateway", "", reason("invalid CIDR"))
	}

	_, v6gw, err := cnet.ParseCIDROrIP(w.IPv6Gateway)
	if err != nil {
		sl.ReportError(reflect.ValueOf(w.IPv6Gateway),
			"IPv6Gateway", "", reason("invalid CIDR"))
	}

	if v4gw.IP != nil && v4gw.Version() != 4 {
		sl.ReportError(reflect.ValueOf(w.IPv4Gateway),
			"IPv4Gateway", "", reason("invalid IPv4 gateway address specified"))
	}

	if v6gw.IP != nil && v6gw.Version() != 6 {
		sl.ReportError(reflect.ValueOf(w.IPv6Gateway),
			"IPv6Gateway", "", reason("invalid IPv6 gateway address specified"))
	}

	// If NATs have been specified, then they should each be within the configured networks of
	// the endpoint.
	if len(w.IPNATs) > 0 {
		valid := false
		for _, nat := range w.IPNATs {
			_, natCidr, err := cnet.ParseCIDROrIP(nat.InternalIP)
			if err != nil {
				sl.ReportError(reflect.ValueOf(nat.InternalIP),
					"IPNATs", "", reason("invalid InternalIP CIDR"))
			}
			// Check each NAT to ensure it is within the configured networks.  If any
			// are not then exit without further checks.
			valid = false
			for _, cidr := range w.IPNetworks {
				_, nw, err := cnet.ParseCIDROrIP(cidr)
				if err != nil {
					sl.ReportError(reflect.ValueOf(cidr),
						"IPNetworks", "", reason("invalid CIDR"))
				}

				if nw.Contains(natCidr.IP) {
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
				"IPNATs", "", reason("NAT is not in the endpoint networks"))
		}
	}
}

func validateHostEndpointSpec(sl validator.StructLevel) {
	h := sl.Current().Interface().(api.HostEndpointSpec)

	// A host endpoint must have an interface name and/or some expected IPs specified.
	if h.InterfaceName == "" && len(h.ExpectedIPs) == 0 {
		sl.ReportError(reflect.ValueOf(h.InterfaceName),
			"InterfaceName", "", reason("no interface or expected IPs have been specified"))
	}
}

func validateIPPoolSpec(sl validator.StructLevel) {
	pool := sl.Current().Interface().(api.IPPoolSpec)

	// Spec.CIDR field must not be empty.
	if pool.CIDR == "" {
		sl.ReportError(reflect.ValueOf(pool.CIDR),
			"IPpool.CIDR", "", reason("IPPool CIDR must be specified"))
	}

	// Make sure the CIDR is parsable.
	ipAddr, cidr, err := cnet.ParseCIDROrIP(pool.CIDR)
	if err != nil {
		sl.ReportError(reflect.ValueOf(pool.CIDR),
			"IPpool.CIDR", "", reason("IPPool CIDR must be a valid subnet"))
	}

	// Normalize the CIDR before persisting.
	pool.CIDR = cidr.String()

	// IPIP cannot be enabled for IPv6.
	if cidr.Version() == 6 && pool.IPIPMode != api.IPIPModeNever {
		sl.ReportError(reflect.ValueOf(pool.IPIPMode),
			"IPpool.IPIPMode", "", reason("IPIPMode other than 'Never' is not supported on an IPv6 IP pool"))
	}

	// The Calico IPAM places restrictions on the minimum IP pool size.  If
	// the ippool is enabled, check that the pool is at least the minimum size.
	if !pool.Disabled {
		ones, bits := cidr.Mask.Size()
		log.Debugf("Pool CIDR: %s, num bits: %d", cidr.String(), bits-ones)
		if bits-ones < 6 {
			if cidr.Version() == 4 {
				sl.ReportError(reflect.ValueOf(pool.CIDR),
					"IPpool.CIDR", "", reason(poolSmallIPv4))
			} else {
				sl.ReportError(reflect.ValueOf(pool.CIDR),
					"IPpool.CIDR", "", reason(poolSmallIPv6))
			}
		}
	}

	// The Calico CIDR should be strictly masked
	log.Debugf("IPPool CIDR: %s, Masked IP: %d", pool.CIDR, cidr.IP)
	if cidr.IP.String() != ipAddr.String() {
		sl.ReportError(reflect.ValueOf(pool.CIDR),
			"IPpool.CIDR", "", reason(poolUnstictCIDR))
	}

	// IPv4 link local subnet.
	ipv4LinkLocalNet := net.IPNet{
		IP:   net.ParseIP("169.254.0.0"),
		Mask: net.CIDRMask(16, 32),
	}
	// IPv6 link local subnet.
	ipv6LinkLocalNet := net.IPNet{
		IP:   net.ParseIP("fe80::"),
		Mask: net.CIDRMask(10, 128),
	}

	// IP Pool CIDR cannot overlap with IPv4 or IPv6 link local address range.
	if cidr.Version() == 4 && cidr.IsNetOverlap(ipv4LinkLocalNet) {
		sl.ReportError(reflect.ValueOf(pool.CIDR),
			"IPpool.CIDR", "", reason(overlapsV4LinkLocal))
	}

	if cidr.Version() == 6 && cidr.IsNetOverlap(ipv6LinkLocalNet) {
		sl.ReportError(reflect.ValueOf(pool.CIDR),
			"IPpool.CIDR", "", reason(overlapsV6LinkLocal))
	}
}

func validateICMPFields(sl validator.StructLevel) {
	icmp := sl.CurrentStruct.Interface().(api.ICMPFields)

	// Due to Kernel limitations, ICMP code must always be specified with a type.
	if icmp.Code != nil && icmp.Type == nil {
		sl.ReportError(reflect.ValueOf(icmp.Code),
			"Code", "", reason("ICMP code specified without an ICMP type"))
	}
}

func validateRule(sl validator.StructLevel) {
	rule := sl.Current().Interface().(api.Rule)

	// If the protocol is neither tcp (6) nor udp (17) check that the port values have not
	// been specified.
	if rule.Protocol == nil || !rule.Protocol.SupportsPorts() {
		if len(rule.Source.Ports) > 0 {
			sl.ReportError(reflect.ValueOf(rule.Source.Ports),
				"Source.Ports", "", reason(protocolPortsMsg))
		}
		if len(rule.Source.NotPorts) > 0 {
			sl.ReportError(reflect.ValueOf(rule.Source.NotPorts),
				"Source.NotPorts", "", reason(protocolPortsMsg))
		}

		if len(rule.Destination.Ports) > 0 {
			sl.ReportError(reflect.ValueOf(rule.Destination.Ports),
				"Destination.Ports", "", reason(protocolPortsMsg))
		}
		if len(rule.Destination.NotPorts) > 0 {
			sl.ReportError(reflect.ValueOf(rule.Destination.NotPorts),
				"Destination.NotPorts", "", reason(protocolPortsMsg))
		}
	}

	var seenV4, seenV6 bool

	scanNets := func(nets []string, fieldName string) {
		var v4, v6 bool
		for _, n := range nets {
			_, cidr, err := cnet.ParseCIDR(n)
			if err != nil {
				sl.ReportError(reflect.ValueOf(n), fieldName,
					"", reason("invalid CIDR"))
			} else {
				v4 = v4 || cidr.Version() == 4
				v6 = v6 || cidr.Version() == 6
			}
		}
		if rule.IPVersion != nil && ((v4 && *rule.IPVersion != 4) || (v6 && *rule.IPVersion != 6)) {
			sl.ReportError(reflect.ValueOf(rule.Source.Nets), fieldName,
				"", reason("rule IP version doesn't match CIDR version"))
		}
		if v4 && seenV6 || v6 && seenV4 || v4 && v6 {
			// This field makes the rule inconsistent.
			sl.ReportError(reflect.ValueOf(nets), fieldName,
				"", reason("rule contains both IPv4 and IPv6 CIDRs"))
		}
		seenV4 = seenV4 || v4
		seenV6 = seenV6 || v6
	}

	scanNets(rule.Source.Nets, "Source.Nets")
	scanNets(rule.Source.NotNets, "Source.NotNets")
	scanNets(rule.Destination.Nets, "Destination.Nets")
	scanNets(rule.Destination.NotNets, "Destination.NotNets")
}

func validateNodeSpec(sl validator.StructLevel) {
	ns := sl.Current().Interface().(api.NodeSpec)

	if ns.BGP != nil {
		if ns.BGP.IPv4Address == "" && ns.BGP.IPv6Address == "" {
			sl.ReportError(reflect.ValueOf(ns.BGP.IPv4Address),
				"BGP.IPv4Address", "", reason("no BGP IP address and subnet specified"))
		}
	}
}

func validateEndpointPort(sl validator.StructLevel) {
	port := sl.Current().Interface().(api.EndpointPort)

	if port.Protocol.String() != "TCP" && port.Protocol.String() != "UDP" {
		sl.ReportError(
			reflect.ValueOf(port.Protocol),
			"EndpointPort.Protocol",
			"",
			reason("EndpointPort protocol must be 'TCP' or 'UDP'."),
		)
	}
}

func validateProtocol(sl validator.StructLevel) {
	p := sl.Current().Interface().(numorstring.Protocol)
	log.Debugf("Validate protocol: %v %s %d", p.Type, p.StrVal, p.NumVal)

	// The protocol field may be an integer 1-255 (i.e. not 0), or one of the valid protocol
	// names.
	if num, err := p.NumValue(); err == nil {
		if num == 0 {
			sl.ReportError(reflect.ValueOf(p.NumVal),
				"Protocol", "", reason("protocol number invalid"))
		}
	} else if !protocolRegex.MatchString(p.String()) {
		sl.ReportError(reflect.ValueOf(p.String()),
			"Protocol", "", reason("protocol name invalid"))
	}
}

func validateProtoPort(sl validator.StructLevel) {
	m := sl.Current().Interface().(api.ProtoPort)

	if m.Protocol != "TCP" && m.Protocol != "UDP" {
		sl.ReportError(
			reflect.ValueOf(m.Protocol),
			"ProtoPort.Protocol",
			"",
			reason("protocol must be 'TCP' or 'UDP'."),
		)
	}
}

func validateObjectMeta(sl validator.StructLevel) {
	om := sl.Current().Interface().(metav1.ObjectMeta)

	// Check the name is within the max length.
	if len(om.Name) > k8svalidation.DNS1123SubdomainMaxLength {
		sl.ReportError(
			reflect.ValueOf(om.Name),
			"Metadata.Name",
			"",
			reason(fmt.Sprintf("name is too long by %d bytes", len(om.Name)-k8svalidation.DNS1123SubdomainMaxLength)),
		)
	}

	// Uses the k8s DN1123 subdomain format for most resource names.
	matched := nameRegex.MatchString(om.Name)
	if !matched {
		sl.ReportError(
			reflect.ValueOf(om.Name),
			"Metadata.Name",
			"",
			reason("name must consist of lower case alphanumeric characters, '-' or '.' (regex: "+nameSubdomainFmt+")"),
		)
	}

	validateObjectMetaAnnotations(v, structLevel, om.Annotations)
	validateObjectMetaLabels(v, structLevel, om.Labels)
}

func validateNetworkPolicy(sl validator.StructLevel) {
	np := sl.Current().Interface().(api.NetworkPolicy)
	spec := np.Spec

	// Check (and disallow) any repeats in Types field.
	mp := map[api.PolicyType]bool{}
	for _, t := range spec.Types {
		if _, exists := mp[t]; exists {
			sl.ReportError(reflect.ValueOf(spec.Types),
				"NetworkPolicySpec.Types", "", reason("'"+string(t)+"' type specified more than once"))
		} else {
			mp[t] = true
		}
	}

	// Check the name is within the max length.
	if len(np.Name) > k8svalidation.DNS1123SubdomainMaxLength {
		sl.ReportError(
			reflect.ValueOf(np.Name),
			"Metadata.Name",
			"",
			reason(fmt.Sprintf("name is too long by %d bytes", len(np.Name)-k8svalidation.DNS1123SubdomainMaxLength)),
		)
	}

	// Uses the k8s DN1123 label format for policy names (plus knp.default prefixed k8s policies).
	matched := networkPolicyNameRegex.MatchString(np.Name)
	if !matched {
		sl.ReportError(
			reflect.ValueOf(np.Name),
			"Metadata.Name",
			"",
			reason("name must consist of lower case alphanumeric characters or '-' (regex: "+nameLabelFmt+")"),
		)
	}

	validateObjectMetaAnnotations(v, structLevel, np.Annotations)
	validateObjectMetaLabels(v, structLevel, np.Labels)
}

func validateGlobalNetworkPolicy(sl validator.StructLevel) {
	gnp := sl.Current().Interface().(api.GlobalNetworkPolicy)
	spec := gnp.Spec

	// Check the name is within the max length.
	if len(gnp.Name) > k8svalidation.DNS1123SubdomainMaxLength {
		sl.ReportError(
			reflect.ValueOf(gnp.Name),
			"Metadata.Name",
			"",
			reason(fmt.Sprintf("name is too long by %d bytes", len(gnp.Name)-k8svalidation.DNS1123SubdomainMaxLength)),
		)
	}

	// Uses the k8s DN1123 label format for policy names.
	matched := globalNetworkPolicyNameRegex.MatchString(gnp.Name)
	if !matched {
		sl.ReportError(
			reflect.ValueOf(gnp.Name),
			"Metadata.Name",
			"",
			reason("name must consist of lower case alphanumeric characters or '-' (regex: "+nameLabelFmt+")"),
		)
	}

	validateObjectMetaAnnotations(v, structLevel, gnp.Annotations)
	validateObjectMetaLabels(v, structLevel, gnp.Labels)

	if spec.DoNotTrack && spec.PreDNAT {
		sl.ReportError(reflect.ValueOf(spec.PreDNAT),
			"PolicySpec.PreDNAT", "", reason("PreDNAT and DoNotTrack cannot both be true, for a given PolicySpec"))
	}

	if spec.PreDNAT && len(spec.Egress) > 0 {
		sl.ReportError(reflect.ValueOf(spec.Egress),
			"PolicySpec.Egress", "", reason("PreDNAT PolicySpec cannot have any Egress"))
	}

	if spec.PreDNAT && len(spec.Types) > 0 {
		for _, t := range spec.Types {
			if t == api.PolicyTypeEgress {
				sl.ReportError(reflect.ValueOf(spec.Types),
					"PolicySpec.Types", "", reason("PreDNAT PolicySpec cannot have 'egress' Type"))
			}
		}
	}

	if !spec.ApplyOnForward && (spec.DoNotTrack || spec.PreDNAT) {
		sl.ReportError(reflect.ValueOf(spec.ApplyOnForward),
			"PolicySpec.ApplyOnForward", "", reason("ApplyOnForward must be true if either PreDNAT or DoNotTrack is true, for a given PolicySpec"))
	}

	// Check (and disallow) any repeats in Types field.
	mp := map[api.PolicyType]bool{}
	for _, t := range spec.Types {
		if _, exists := mp[t]; exists {
			sl.ReportError(reflect.ValueOf(spec.Types),
				"GlobalNetworkPolicySpec.Types", "", reason("'"+string(t)+"' type specified more than once"))
		} else {
			mp[t] = true
		}
	}
}

func validateObjectMetaAnnotations(sl validator.StructLevel, annotations map[string]string) {
	var totalSize int64
	for k, v := range annotations {
		for _, errStr := range k8svalidation.IsQualifiedName(strings.ToLower(k)) {
			sl.ReportError(
				reflect.ValueOf(k),
				"Metadata.Annotations (key)",
				"",
				reason(errStr),
			)
		}
		totalSize += (int64)(len(k)) + (int64)(len(v))
	}

	if totalSize > (int64)(totalAnnotationSizeLimitB) {
		sl.ReportError(
			reflect.ValueOf(annotations),
			"Metadata.Annotations (key)",
			"",
			reason(fmt.Sprintf("total size of annotations is too large by %d bytes", totalSize-totalAnnotationSizeLimitB)),
		)
	}
}

func validateObjectMetaLabels(sl validator.StructLevel, labels map[string]string) {
	for k, v := range labels {
		for _, errStr := range k8svalidation.IsQualifiedName(k) {
			sl.ReportError(
				reflect.ValueOf(k),
				"Metadata.Labels (label)",
				"",
				reason(errStr),
			)
		}
		for _, errStr := range k8svalidation.IsValidLabelValue(v) {
			sl.ReportError(
				reflect.ValueOf(v),
				"Metadata.Labels (value)",
				"",
				reason(errStr),
			)
		}
	}
}
