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
	"sync"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
)

// Create a new NewIPPoolUpdateProcessor.
func NewIPPoolUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return &ipPoolUpdateProcessor{
		poolsByCidr: make(map[string][]*model.IPPool),
		cidrByName:  make(map[string]string),
	}
}

// ipPoolUpdateProcessor implements the SyncerUpdateProcessor interface.  IPPool conversion
// is a little tricky because the v1 index is now an arbitrary field in v2.  This means
// update events may trigger v1 deletions, and multiple IP pools may share the same CIDR
// (a misconfiguration, but one we should handle gracefully).
type ipPoolUpdateProcessor struct {
	poolsByCidr map[string][]*model.IPPool
	cidrByName  map[string]string
	lock        sync.Mutex
}

func (c *ipPoolUpdateProcessor) ProcessDeleted(k model.Key) ([]model.Key, error) {
	// Extract the name.
	_, err := c.extractName(k)
	if err != nil {
		return nil, err
	}
	/*
		// Look up the previous pool settings for this name, and remove from the cache.
		previous, ok := c.poolsByName[name]
		if !ok {
			return nil, errors.New("Delete request for unknown pool")
		}
		delete(c.poolsByName, name)

		// If this was the "active" pool for the old CIDR then send the key for delete, otherwise
		// no need to send any events.
		cidr := previous.Key.(model.IPPoolKey).CIDR.String()
		if c.namesByCidr[cidr] == name {
			return []model.Key{previous.Key}, nil
		}
	*/
	return nil, nil
}

func (c *ipPoolUpdateProcessor) Process(kvp *model.KVPair) ([]*model.KVPair, error) {
	// Extract the name.
	_, err := c.extractName(kvp.Key)
	if err != nil {
		return nil, err
	}
	return nil, err
}

// Sync is restarting, clear our local cache.
func (c *ipPoolUpdateProcessor) SyncStarting() {
	c.poolsByCidr = make(map[string][]*model.IPPool)
	c.cidrByName = make(map[string]string)
}

func (c *ipPoolUpdateProcessor) extractName(k model.Key) (string, error) {
	rk, ok := k.(model.ResourceKey)
	if !ok {
		return "", errors.New("Incorrect key type")
	}
	return rk.Name, nil
}
