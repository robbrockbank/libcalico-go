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

/*
import (
	"errors"
	"sync"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
)

// conflictResolvingCache implements a cache that can be used to deterministically
// resolve conflicts where the indexes of the v1 model are no longer indexes in the
// v2 model - this means multiple v2 resource may share common indexing in v1 - e.g.
// IPPools in v2 are indexed by arbitrary name, and in v1 by the Pool CIDR.  Conflicting
// entries resolve to use the v2 resource with the highest alphanumeric name.
type conflictResolvingCache struct {
}

// addUpdate - adds or updates the entry in the cache.  The name is the original
// name of the resource.
func (c *conflictResolvingCache) addUpdate(name string, kvp *model.KVPair) []*model.KVPair {

}

func (c *conflictResolvingCache) delete(name string, key model.Key) []*model.KVPair {

}

ProcessDeleted(k model.Key) ([]model.Key, error) {
}

func (c *conflictResolver) ProcessNewOrUpdated(kvp *model.KVPair) ([]*model.KVPair, error) {
}

// Sync is restarting, clear our local cache.
func (c *conflictResolver) SyncStarting() {
}

func (c *conflictResolver) extractName(k model.Key) (string, error) {
}
*/