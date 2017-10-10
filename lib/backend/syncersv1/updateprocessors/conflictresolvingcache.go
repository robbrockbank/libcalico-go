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
	"fmt"
	"sort"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
)

// ConflictResolvingNameCache implements a cache that may be used to handle resources
// where the indexing has changed between the v2 and v1 models.  In v2 all resources have
// a single name field which in some cases may be unlinked to the v1 indexes.  This means
// it's potentially possible to have multiple v2 resources that share a common set of indexes
// when converted to the v1 model - e.g. IPPools in v2 are indexed by arbitrary name, and in
// v1 by the Pool CIDR, it would be possible to have multiple pools configured with the same
// CIDR.
//
// Notes:
// - generally, validation processing would prevent the user from making configuration
//   changes with conflicting (duplicate) information - but since that operation is not atomic,
//   we need to handle gracefully these situations whether or not that validation processing is
//   in place.
// - since the relationship between the v1 and v2 indexes is not locked, the v1 index
//   for a given v2 resource may be changed by an update.
//
// This cache handles conflicting entries by only syncing the v1 data for the v2 resource with
// the lowest alphanumeric name.  This means:
// -  Adding a conflicting resource with a higher alphanumeric name will not result in any
//    syncer update.
// -  Deleting the conflicting resource with the lowest alphanumeric name will result in
//    an update using the configuration of the conflicting resource with the next lowest
//    alphanumeric name.
// -  Modifying an existing resource (that is already in our cache) is more complicated.
//    It is possible that the modification may alter the v1 key - and in which case we need
//    to effectively treat as a delete (for the old v1 key) and an add for the new v1 key.
func NewConflictResolvingCache() ConflictResolvingCache {
	return &conflictResolvingCache{
		kvpsByName:          make(map[string]*model.KVPair),
		orderedNamesByV1Key: make(map[string][]string),
	}
}

type ConflictResolvingCache interface {
	// AddOrModify adds or updates the entry in the cache and calculates what updates to send
	// to the syncer.  The name is the original name of the v2 resource.  The kvp should be the
	// converted (i.e. v1) model representation.
	//
	// Returns the effective update(s) to send in the syncer.  A nil value in the KVPair
	// indicates a delete, otherwise it's an add/modify.
	AddOrModify(name string, kvp *model.KVPair) ([]*model.KVPair, error)

	// Delete an entry in the cache and calculate what updates to send to the syncer.  The name
	// is the original name of the v2 resource.
	//
	// Returns the effective update(s) to send in the syncer.  A nil value in the KVPair
	// indicates a delete, otherwise it's an add/modify.
	Delete(name string) ([]*model.KVPair, error)

	// Clear the cache.
	ClearCache()
}

// conflictResolvingCache implements the ConflictRecolvingCache interface.
type conflictResolvingCache struct {
	kvpsByName          map[string]*model.KVPair
	orderedNamesByV1Key map[string][]string
}

func (c *conflictResolvingCache) AddOrModify(name string, kvp *model.KVPair) ([]*model.KVPair, error) {
	// Construct the new v1Key string (we just use the default path)
	v1Key, err := model.KeyToDefaultPath(kvp.Key)
	if err != nil {
		return nil, err
	}

	logCxt := log.WithFields(log.Fields{
		"Name": name,
		"Key":  v1Key,
	})

	// If we have a value cached for this name, handle the situation where the v1 key has
	// changed.
	var response []*model.KVPair
	if existing := c.kvpsByName[name]; existing != nil {
		// Get the old key, we know this succeeds because we had to get the default path to put it
		// in the cache.
		oldV1Key, err := model.KeyToDefaultPath(existing.Key)
		cerrors.FatalIfErrored(err)

		// If the key has changed, first handle this as a delete.  This may result in a
		// delete response that we need to include.
		if oldV1Key != v1Key {
			logCxt.WithField("Old key", oldV1Key).Info("key modified, handle delete first")
			response, err = c.Delete(name)
			cerrors.FatalIfErrored(err)
		}
	}

	// Get the current set of names that map to this key, and if this name is not
	// in the list - add it and sort the list.
	cns := c.orderedNamesByV1Key[v1Key]
	inList := false
	for _, cn := range cns {
		if cn == name {
			inList = true
			break
		}
	}
	if !inList {
		cns = append(cns, name)
		sort.Strings(cns)
	}

	// Update our cache.
	c.orderedNamesByV1Key[v1Key] = cns
	c.kvpsByName[name] = kvp

	// If this is the first entry in the list then the kvp should be included in the syncer
	// response.
	if cns[0] == name {
		logCxt.WithField("All conflicting resource names", cns).Debug("non conflicting, or primary resource: sending update")
		response = append(response, kvp)
	} else {
		logCxt.WithFields(log.Fields{
			"All conflicting resource names": cns[0],
		}).Warning("conflicting resources and this is not the primary resource: swallowing update")
	}

	return response, nil
}

// delete - deletes the entry in the cache.  The name is the original name of the v2
// resource.
//
// Returns the effective update(s) to send in the syncer.  A nil value in the KVPair
// indicates a delete, otherwise it's an add/modify.
func (c *conflictResolvingCache) Delete(name string) ([]*model.KVPair, error) {
	logCxt := log.WithField("Name", name)

	// Get the data that we currently have stored in our cache for this resource name.
	kvp := c.kvpsByName[name]
	if kvp == nil {
		return nil, fmt.Errorf("delete called for unknown resource: %s", name)
	}

	// Calculate the key for that resource.  This should succeed because we already called
	// this to get the entry in the cache.
	v1Key, err := model.KeyToDefaultPath(kvp.Key)
	cerrors.FatalIfErrored(err)

	// Get the current set of names that map to this key and use this to determine what
	// updates to send.
	cns := c.orderedNamesByV1Key[v1Key]

	// If this is the primary resource in the v1 model then we either need to delete if
	// there are no conflicting resources, or send an update for the new primary resource.
	var response []*model.KVPair
	if cns[0] == name {
		logCxt.WithField("All conflicting resource names", cns).Debug("non conflicting, or primary resource deleted: sending update")

		if len(cns) == 1 {
			// There are no conflicting entries, so send a delete for this v1 key.
			logCxt.Debug("no conflicting entries: sending delete")
			response = []*model.KVPair{{
				Key: kvp.Key,
			}}
		} else {
			// There is a new primary resource (the next entry in the ordered list of names) for
			// the set of conflicting v1 keys.  Send an update using the new primary resource
			// configuration - looking up the stored details by name.
			logCxt.WithField("Primary resource", cns[1]).Debug("conflicting entries: sending update for new primary")
			kvp := c.kvpsByName[cns[1]]
			response = []*model.KVPair{kvp}
		}
	} else {
		logCxt.WithFields(log.Fields{
			"All conflicting resource names": cns,
		}).Warning("conflicting resources and this is not the primary resource: swallowing update")
	}

	// Update the cache.
	delete(c.kvpsByName, name)

	if len(cns) == 1 {
		// Ours was the only entry in the conflicting names list, so just remove the set
		// in its entirety.
		delete(c.orderedNamesByV1Key, v1Key)
	} else {
		// Ours was not the only entry in the conflicting names list, so remove our entry
		// and update the cache (keeping the list ordered).
		newCns := make([]string, len(cns)-1)
		i := 0
		for _, cn := range cns {
			if cn != name {
				newCns[i] = cn
				i++
			}
		}
		c.orderedNamesByV1Key[v1Key] = newCns
	}

	return response, nil
}

// ClearCache removes all entries from the cache.
func (c *conflictResolvingCache) ClearCache() {
	log.Debug("Clearing cache data")
	c.kvpsByName = make(map[string]*model.KVPair)
	c.orderedNamesByV1Key = make(map[string][]string)
}
