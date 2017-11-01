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

package multisyncer

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
)

const (
	maxUpdatesToConsolidate = 1000
)

// New creates a new multiple syncer-backed api.Syncer.
func New(syncerFactories []api.SyncerFactory, callbacks api.SyncerCallbacks) api.Syncer {
	ms := &multiSyncer{
		syncers:   make([]api.Syncer, len(syncerFactories)),
		results:   make(chan interface{}, 2000),
		callbacks: callbacks,
	}
	for i, sf := range syncerFactories {
		sr := &syncerReceiver{ms: ms, sf: sf}
		ms.syncers[i] = sf.Syncer(sr)
	}
	return ms
}

// multiSyncer implements the api.Syncer interface.
type multiSyncer struct {
	status    api.SyncStatus
	syncers   []api.Syncer
	results   chan interface{}
	numSynced int
	callbacks api.SyncerCallbacks
}

func (ms *multiSyncer) Start() {
	log.Info("Start called")
	go ms.run()
}

// Send a status update and store the status.
func (ms *multiSyncer) sendStatusUpdate(status api.SyncStatus) {
	log.WithField("Status", status).Info("Sending status update")
	ms.callbacks.OnStatusUpdated(status)
	ms.status = status
}

// run implements the main syncer loop that loops forever receiving watch events and translating
// to syncer updates.
func (ms *multiSyncer) run() {
	log.Debug("Sending initial status event and starting watchers")
	ms.sendStatusUpdate(api.WaitForDatastore)
	for _, s := range ms.syncers {
		s.Start()
	}

	log.Info("Starting multi-syncer event loop")
	var updates []api.Update
	for {
		// Block until there is data.
		result := <-ms.results

		// Process the data - this will append the data in subsequent calls, and action
		// it if we hit a non-update event.
		updates := ms.processResult(updates, result)

		// Append results into the one update until we either flush the channel or we
		// hit our fixed limit per update.
	consolidatationloop:
		for ii := 0; ii < maxUpdatesToConsolidate; ii++ {
			select {
			case next := <-ms.results:
				updates = ms.processResult(updates, next)
			default:
				break consolidatationloop
			}
		}

		// Perform final processing (pass in a nil result) before we loop and hit the blocking
		// call again.
		updates = ms.sendUpdates(updates)
	}
}

// Process a result from the result channel.  We don't immediately action updates, but
// instead start grouping them together so that we can send a larger single update to
// Felix.
func (ms *multiSyncer) processResult(updates []api.Update, result interface{}) []api.Update {

	// Switch on the result type.
	switch r := result.(type) {
	case []api.Update:
		// This is an update.  If we don't have previous updates then also check to see
		// if we need to shift the status into Resync.
		// We append these updates to the previous if there were any.
		if len(updates) == 0 && ms.status == api.WaitForDatastore {
			ms.sendStatusUpdate(api.ResyncInProgress)
		}
		updates = append(updates, r...)

	case error:
		// Received an error.  Firstly, send any updates that we have grouped.
		updates = ms.sendUpdates(updates)

		// If this is a parsing error, and if the callbacks support
		// it, then send the error update.
		log.WithError(r).Info("Error received in main syncer event processing loop")
		if ec, ok := ms.callbacks.(api.SyncerParseFailCallbacks); ok {
			log.Debug("syncer receiver can receive parse failed callbacks")
			if pe, ok := r.(cerrors.ErrorParsingDatastoreEntry); ok {
				ec.ParseFailed(pe.RawKey, pe.RawValue)
			}
		}

	case api.SyncStatus:
		// Received a synced event.  If we are still waiting for datastore, send a
		// ResyncInProgress since at least one watcher has connected.
		log.WithField("SyncUpdate", r).Debug("Received sync status event from watcher")
		if r == api.InSync {
			log.Info("Received InSync event from one of the watcher caches")

			if ms.status == api.WaitForDatastore {
				ms.sendStatusUpdate(api.ResyncInProgress)
			}

			// Increment the count of synced events.
			ms.numSynced++

			// If we have now received synced events from all of our watchers then we are in
			// sync.  If we have any updates, send them first and then send the status update.
			if ms.numSynced == len(ms.syncers) {
				log.Info("All watchers have sync'd data - sending data and final sync")
				updates = ms.sendUpdates(updates)
				ms.sendStatusUpdate(api.InSync)
			}
		}
	}

	// Return the accumulated or processed updated.
	return updates
}

// sendUpdates is used to send the consoidated set of updates.  Returns nil.
func (ms *multiSyncer) sendUpdates(updates []api.Update) []api.Update {
	log.WithField("NumUpdates", len(updates)).Debug("Sending syncer updates (if any to send)")
	if len(updates) > 0 {
		ms.callbacks.OnUpdates(updates)
	}
	return nil
}

// syncerReceiver implements the api.SyncerCallbacks and api.SyncerParseFailCallbacks interfaces
// and is used to receive events from an individual syncer.
type syncerReceiver struct {
	sf     api.SyncerFactory
	ms     *multiSyncer
	inSync bool
}

func (sr *syncerReceiver) OnStatusUpdated(status api.SyncStatus) {
	if status == api.InSync {
		if sr.inSync {
			// The syncer implementation is expected to only return InSync once.
			log.WithField("SyncerFactory", sr.sf).Fatal("Multiple InSync messages received from syncer")
		}
		sr.inSync = true
		sr.ms.results <- status
	}
}

func (sr *syncerReceiver) OnUpdates(updates []api.Update) {
	sr.ms.results <- updates
}

func (sr *syncerReceiver) ParseFailed(rawKey string, rawValue string) {
	sr.ms.results <- cerrors.ErrorParsingDatastoreEntry{
		RawKey:   rawKey,
		RawValue: rawValue,
	}
}
