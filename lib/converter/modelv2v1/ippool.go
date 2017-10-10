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

package modelv2v1

import (
	"errors"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/ipip"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

// IPPoolConverter implements a set of functions used for converting between
// API and backend representations of the IPPool resource.
type IPPoolConverter struct{}

// Convert v2 KVPair to the equivalent v1 KVPair.
func (p IPPoolConverter) ConvertV2ToV1(kvp *model.KVPair) (*model.KVPair, error) {
	if rk, ok := kvp.Key.(model.ResourceKey); !ok || rk.Kind != apiv2.KindIPPool {
		return nil, errors.New("Key is not a valid IP Pool resource key")
	} else if p, ok := kvp.Value.(*apiv2.IPPool); !ok {
		return nil, errors.New("Value is not a valid IP Pool resource key")
	} else {
		_, cidr, err := cnet.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			return nil, err
		}
		v1key := model.IPPoolKey{
			CIDR: *cidr,
		}
		var ipipInterface string
		var ipipMode ipip.Mode
		var ipm apiv2.IPIPMode
		if p.Spec.IPIP != nil {
			ipm = p.Spec.IPIP.Mode
		}
		switch ipm {
		case apiv2.IPIPModeOff:
			ipipInterface = ""
			ipipMode = ipip.Undefined
		case apiv2.IPIPModeCrossSubnet:
			ipipInterface = "tunl0"
			ipipMode = ipip.CrossSubnet
		default:
			ipipInterface = "tunl0"
			ipipMode = ipip.Always
		}

		return &model.KVPair{
			Key: v1key,
			Value: &model.IPPool{
				CIDR:          *cidr,
				IPIPInterface: ipipInterface,
				IPIPMode:      ipipMode,
				Masquerade:    p.Spec.NATOutgoing,
				IPAM:          !p.Spec.Disabled,
				Disabled:      p.Spec.Disabled,
			},
			Revision: kvp.Revision,
		}, nil
	}
}
