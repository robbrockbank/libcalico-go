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

package felixsyncer

import (
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/multisyncer"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
)

// New creates a new Felix v1 Syncer.  Currently only the etcdv3 backend is supported
// since KDD does not yet fully support Watchers.
func New(client api.Client, callbacks api.SyncerCallbacks, datastoreType apiconfig.DatastoreType) api.Syncer {
	// Create the set of SyncerFactory interfaces required for Felix.
	syncerFactories := []api.SyncerFactory{
		watchersyncer.Factory{
			ListInterface:   model.ResourceListOptions{Kind: apiv2.KindClusterInformation},
			UpdateProcessor: updateprocessors.NewClusterInfoUpdateProcessor(),
		},
		watchersyncer.Factory{
			ListInterface:   model.ResourceListOptions{Kind: apiv2.KindFelixConfiguration},
			UpdateProcessor: updateprocessors.NewFelixConfigUpdateProcessor(),
		},
		watchersyncer.Factory{
			ListInterface:   model.ResourceListOptions{Kind: apiv2.KindGlobalNetworkPolicy},
			UpdateProcessor: updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(),
		},
		watchersyncer.Factory{
			ListInterface:   model.ResourceListOptions{Kind: apiv2.KindIPPool},
			UpdateProcessor: updateprocessors.NewIPPoolUpdateProcessor(),
		},
		watchersyncer.Factory{
			ListInterface:   model.ResourceListOptions{Kind: apiv2.KindNode},
			UpdateProcessor: updateprocessors.NewFelixNodeUpdateProcessor(),
		},
		watchersyncer.Factory{
			ListInterface:   model.ResourceListOptions{Kind: apiv2.KindProfile},
			UpdateProcessor: updateprocessors.NewProfileUpdateProcessor(),
		},
		watchersyncer.Factory{
			ListInterface:   model.ResourceListOptions{Kind: apiv2.KindWorkloadEndpoint},
			UpdateProcessor: updateprocessors.NewWorkloadEndpointUpdateProcessor(),
		},
		watchersyncer.Factory{
			ListInterface:   model.ResourceListOptions{Kind: apiv2.KindNetworkPolicy},
			UpdateProcessor: updateprocessors.NewNetworkPolicyUpdateProcessor(),
		},
	}

	if datastoreType != apiconfig.Kubernetes {
		// Kubernetes does not yet support HostEndpoints, so only included for non-Kubernetes.
		syncerFactories = append(syncerFactories,
			watchersyncer.Factory{
				ListInterface:   model.ResourceListOptions{Kind: apiv2.KindHostEndpoint},
				UpdateProcessor: updateprocessors.NewHostEndpointUpdateProcessor(),
			},
		)
	}

	return multisyncer.New(syncerFactories, callbacks)
}
