// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package resourcemgr

import (
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/api/unversioned"
	"github.com/tigera/libcalico-go/lib/client"
)

func init() {
	registerResource(
		api.NewProfile(),
		api.NewProfileList(),
		[]string{"NAME"},
		[]string{"NAME", "TAGS"},
		map[string]string{
			"NAME": "{{.Metadata.Name}}",
			"TAGS": "{{join .Spec.Tags \",\"}}",
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Profile)
			return client.Profiles().Apply(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Profile)
			return client.Profiles().Create(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Profile)
			return client.Profiles().Update(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Profile)
			return nil, client.Profiles().Delete(r.Metadata)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Profile)
			return client.Profiles().List(r.Metadata)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Profile)
			return client.Profiles().Get(r.Metadata)
		},
	)
}
