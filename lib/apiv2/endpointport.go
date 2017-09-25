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

package apiv2

import 	"github.com/projectcalico/libcalico-go/lib/numorstring"

type EndpointPort struct {
	Name     string               `json:"name" validate:"portname"`
	Protocol numorstring.Protocol `json:"protocol"`
	Port     uint16               `json:"port" validate:"gt=0"`
}


