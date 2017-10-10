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

package updateprocessors

import (
	"errors"

	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
	"github.com/projectcalico/libcalico-go/lib/converter/modelv2v1"
)

// Create a new NewIPPoolUpdateProcessor.
func NewIPPoolUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return &ipPoolUpdateProcessor{
		cache: NewConflictResolvingCache(),
	}
}

// ipPoolUpdateProcessor implements the SyncerUpdateProcessor interface.
// Most of the heavy lifting is handled by the convert functions (to convert a v2 resource
// to a v1 key and value), and the ConflictResolvingCache which handles the different
// indexing between v2 and v2 and provides deterministic conflict resolution.
type ipPoolUpdateProcessor struct {
	cache ConflictResolvingCache
	modelv2v1.IPPoolConverter
}

func (c *ipPoolUpdateProcessor) Process(kvp *model.KVPair) ([]*model.KVPair, error) {
	// Extract the name.
	name, err := c.extractName(kvp.Key)
	if err != nil {
		return nil, err
	}

	// For a delete, we just call through to the cache - it will provide the syncer updates
	// for the delete based on the v2 resource name.
	if kvp.Value == nil {
		return c.cache.Delete(name)
	}

	// For an add/update we need to convert the v2 resource to the appropriate v1 Key and
	// model value.
	kvp, err = c.ConvertV2ToV1(kvp)
	if err != nil {
		return nil, err
	}

	// And use the cache to handle conflicts.
	return c.cache.AddOrModify(name, kvp)
}

// Sync is restarting, clear our local cache.
func (c *ipPoolUpdateProcessor) SyncStarting() {
	c.cache.ClearCache()
}

func (c *ipPoolUpdateProcessor) extractName(k model.Key) (string, error) {
	rk, ok := k.(model.ResourceKey)
	if !ok || rk.Kind != apiv2.KindIPPool {
		return "", errors.New("Incorrect key type")
	}
	return rk.Name, nil
}
