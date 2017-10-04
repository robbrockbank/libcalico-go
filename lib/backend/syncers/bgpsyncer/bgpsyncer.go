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

package bgpsyncer

import (
	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
	"github.com/projectcalico/libcalico-go/lib/backend/syncers/updateprocessors"
)


// New creates a new Felix v1 Syncer.  Currently only the etcdv3 backend is supported
// since KDD does not yet fully support Watchers.
func New(client api.Client, callbacks api.SyncerCallbacks) api.Syncer {
	// Create the set of ResourceTypes required for Felix.  Since the update processors
	// also cache state, we need to create individual ones per syncer rather than create
	// a common global set.
	resourceTypes := []watchersyncer.ResourceType{
		{
			ListInterface: model.ResourceListOptions{Kind: apiv2.KindIPPool},
			Converter:     updateprocessors.NewIPPoolUpdateProcessor(),
		},
		{
			ListInterface: model.ResourceListOptions{Kind: apiv2.KindBGPConfiguration},
			Converter:     updateprocessors.NewFelixConfigUpdateProcessor(),
		},
		{
			ListInterface: model.ResourceListOptions{Kind: apiv2.KindNode},
		},
		{
			ListInterface: model.ResourceListOptions{Kind: apiv2.KindBGPPeer},
		},
	}

	return watchersyncer.New(
		client,
		resourceTypes,
		callbacks,
	)
}
