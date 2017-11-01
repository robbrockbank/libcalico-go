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

package watchersyncer

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
)

func New(
	client api.Client,
	listInterface model.ListInterface,
	updateProcessor SyncerUpdateProcessor,
	syncerCallbacks api.SyncerCallbacks,
) api.Syncer {
	// Validate the resourceType contains the minimum required config.
	if listInterface == nil {
		logrus.Fatal("SyncerWatcher resource ListInterface not specified")
	}
	return &watcherSyncer{
		logger:            logrus.WithField("ListRoot", model.ListOptionsToDefaultPathRoot(listInterface)),
		client:            client,
		listInterface:     listInterface,
		updateProcessor:   updateProcessor,
		syncerCallbacks:   syncerCallbacks,
		resourceRevisions: make(map[string]string, 0),
		status:            api.WaitForDatastore,
	}
}

// SyncerUpdateProcessor is used to convert a Watch update into one or more additional
// Syncer updates.
type SyncerUpdateProcessor interface {
	// Process is called to process a watch update.  The processor may convert this
	// to zero or more updates.  The processor may use these calls to maintain a local cache
	// if required.  It is safe for the processor to send multiple duplicate adds or deletes
	// since the WatcherSyncer maintains it's own cache and will swallow duplicates.
	// A KVPair with a nil value indicates a delete.  A non nil value indicates an add/modified.
	// The processor may respond with any number of adds or deletes.
	// If the resource cannot be converted then the update processor should treat this as a
	// delete event and return the appropriate delete keys where possible.
	Process(*model.KVPair) ([]*model.KVPair, error)

	// OnSyncerStarting is called when syncer is starting a full sync for the associated resource
	// type.  That means it is first going to list current resources and then watch for any updates.
	// If the processor maintains a private internal cache, then the cache should be cleared at
	// this point since the cache will be re-populated from the sync.
	OnSyncerStarting()
}

// WatcherSyncerFactory implements the api.SyncerFactory.
type Factory struct {
	Client          api.Client
	ListInterface   model.ListInterface
	UpdateProcessor SyncerUpdateProcessor
}

// Return a Syncer using the supplied callbacks.
func (wsf Factory) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	return New(
		wsf.Client,
		wsf.ListInterface,
		wsf.UpdateProcessor,
		callbacks,
	)
}

// The watcherSyncer implements the api.Syncer interface and provides watcher/syncer support
// for a single key type in the backend api.  The supplied update processor may convert the
// events into multiple alternative events or different types.
type watcherSyncer struct {
	logger          *logrus.Entry
	client          api.Client
	listInterface   model.ListInterface
	updateProcessor SyncerUpdateProcessor
	syncerCallbacks api.SyncerCallbacks
	watch           api.WatchInterface
	status          api.SyncStatus

	// Resources revisions keyed off the stringified model.Key.
	resourceRevisions    map[string]string
	oldResourceRevisions map[string]string
}

var (
	ListRetryInterval = 1000 * time.Millisecond
	WatchPollInterval = 5000 * time.Millisecond
)

func (ws *watcherSyncer) Start() {
	ws.logger.Info("Start called")
	go ws.run()
}

// run creates the watcher and loops indefinitely reading from the watcher.
func (ws *watcherSyncer) run() {
	ws.logger.Debug("Watcher syncer starting, start initial sync processing")
	ws.syncerCallbacks.OnStatusUpdated(api.WaitForDatastore)
	ws.resyncAndCreateWatcher()

	ws.logger.Debug("Starting main event processing loop")
	for {
		rc := ws.watch.ResultChan()
		ws.logger.WithField("RC", rc).Debug("Reading event from results channel")
		event := <-rc
		switch event.Type {
		case api.WatchAdded, api.WatchModified:
			kvp := event.New
			ws.handleWatchListEvent(kvp)
		case api.WatchDeleted:
			// Nil out the value to indicate a delete.
			kvp := event.Old
			kvp.Value = nil
			ws.handleWatchListEvent(kvp)
		case api.WatchError:
			// Handle a WatchError.  First determine if the error type indicates that the
			// watch has closed, and if so we'll need to resync and create a new watcher, otherwise
			// use the handleError method to process.
			if wte, ok := event.Error.(cerrors.ErrorWatchTerminated); ok {
				ws.logger.WithError(wte).Info("Received watch terminated error - recreate watcher")
				ws.resyncAndCreateWatcher()
			} else {
				ws.handleError(event.Error)
			}
		default:
			// Unknown event type - not much we can do other than log.
			ws.logger.WithField("EventType", event.Type).Info("Unknown event type received from the datastore")
		}
	}
}

// resyncAndCreateWatcher loops performing resync processing until it successfully
// completes a resync and starts a watcher.
func (ws *watcherSyncer) resyncAndCreateWatcher() {
	// Make sure any previous watcher is stopped.
	ws.logger.Info("Starting watch sync/resync processing")
	if ws.watch != nil {
		ws.logger.Info("Stopping previous watcher")
		ws.watch.Stop()
		ws.watch = nil
	}

	for {
		// Start the resync.  This processing loops until we create the watcher.  If the
		// watcher continuously fails then this loop effectively becomes a polling based
		// syncer.
		ws.logger.Debug("Starting main resync loop")

		// Notify the converter that we are resyncing.
		if ws.updateProcessor != nil {
			ws.logger.Debug("Trigger converter resync notification")
			ws.updateProcessor.OnSyncerStarting()
		}

		// Start the sync by Listing the current resources.
		l, err := ws.client.List(context.Background(), ws.listInterface, "")
		if err != nil {
			// Failed to perform the list.  Pause briefly (so we don't tight loop) and retry.
			ws.logger.WithError(err).Info("Failed to perform list of current data during resync")
			time.Sleep(ListRetryInterval)
			continue
		}

		// If we are in the WaitingForDatastore state, update to be ResyncInProgress.
		if ws.status == api.WaitForDatastore {
			ws.logger.Info("Sending ResyncInProgress status update")
			ws.status = api.ResyncInProgress
			ws.syncerCallbacks.OnStatusUpdated(api.ResyncInProgress)
		}

		// Move the current resources over to the oldResources
		ws.oldResourceRevisions = ws.resourceRevisions
		ws.resourceRevisions = make(map[string]string, 0)

		// Send updates for each of the resources we listed - this will revalidate entries in
		// the oldResources map.
		for _, kvp := range l.KVPairs {
			ws.handleWatchListEvent(kvp)
		}

		// We've listed the current settings.  Complete the sync by notifying the main WatcherSyncer
		// go routine (if we haven't already) and by sending deletes for the old resources that were
		// not acknowledged by the List.  The oldResources will be empty after this call.
		ws.finishResync()

		// And now start watching from the revision returned by the List.
		w, err := ws.client.Watch(context.Background(), ws.listInterface, l.Revision)
		if err != nil {
			// Failed to create the watcher - we'll need to retry.  Sleep so that we don't
			// tight loop.  Since we have just performed a list, we need a slightly longer
			// delay to avoid overloading the datastore.  If the watcher keeps failing then
			// we are effectively operating in a polling mode, so the interval should be a
			// sensible polling interval.  Some resource types cannot be watched, so receiving
			// an error here is not necessarily an error condition.
			ws.logger.WithError(err).Debug("Failed to create watcher")
			time.Sleep(WatchPollInterval)
			continue
		}

		// Store the watcher and exit back to the main event loop.
		ws.logger.Debug("Resync completed, now watching for change events")
		ws.watch = w
		return
	}
}

// finishResync handles processing to finish synchronization.
// If this watcher has never been synced then notify the main watcherSyncer that we've synced.
// We may also need to send deleted messages for old resources that were not validated in the
// resync (i.e. they must have since been deleted).
func (ws *watcherSyncer) finishResync() {
	// If this is our first synced event then send a synced notification.  The main
	// watcherSyncer code will send a Synced event when it has received synced events from
	// each cache.
	if ws.status != api.InSync {
		ws.logger.Info("Sending InSync status update")
		ws.syncerCallbacks.OnStatusUpdated(api.InSync)
		ws.status = api.InSync
	}

	// If the watcher failed at any time, we end up recreating a watcher and storing off
	// the current known resources for revalidation.  Now that we have finished the sync,
	// any of the remaining resources that were not accounted for must have been deleted
	// and we need to send deleted events for them.
	numOldResources := len(ws.oldResourceRevisions)
	if numOldResources > 0 {
		ws.logger.WithField("Num", numOldResources).Debug("Sending resync deletes")
		updates := make([]api.Update, 0, len(ws.oldResourceRevisions))
		for keyString := range ws.oldResourceRevisions {
			key := model.KeyFromDefaultPath(keyString)
			updates = append(updates, api.Update{
				UpdateType: api.UpdateTypeKVDeleted,
				KVPair: model.KVPair{
					Key: key,
				},
			})
		}
		ws.syncerCallbacks.OnUpdates(updates)
	}
	ws.oldResourceRevisions = nil
}

// handleWatchListEvent handles a watch event converting it if required and passing to
// handleConvertedWatchEvent to send the appropriate update types.
func (ws *watcherSyncer) handleWatchListEvent(kvp *model.KVPair) {
	if ws.updateProcessor == nil {
		// No update processor - handle immediately.
		ws.handleConvertedWatchEvent(kvp)
		return
	}

	// We have an update processor so use that to convert the event data.
	kvps, err := ws.updateProcessor.Process(kvp)
	for _, kvp := range kvps {
		ws.handleConvertedWatchEvent(kvp)
	}

	// If we hit a conversion error, notify the main syncer.
	if err != nil {
		ws.handleError(err)
	}
}

// handleConvertedWatchEvent handles a converted watch event fanning out
// to the add/mod or delete processing as necessary.
func (ws *watcherSyncer) handleConvertedWatchEvent(kvp *model.KVPair) {
	if kvp.Value == nil {
		ws.handleDeletedUpdate(kvp.Key)
	} else {
		ws.handleAddedOrModifiedUpdate(kvp)
	}
}

// handleAddedOrModifiedUpdate handles a single Added or Modified update request.
// Whether we send an Added or Modified depends on whether we have already sent
// an added notification for this resource.
func (ws *watcherSyncer) handleAddedOrModifiedUpdate(kvp *model.KVPair) {
	thisKey := kvp.Key
	thisKeyString, err := model.KeyToDefaultPath(thisKey)
	if err != nil {
		ws.logger.WithError(err).WithField("Key", thisKey).Error("Unable to convert Key to string")
		return
	}
	thisRevision := kvp.Revision
	ws.markAsValid(thisKeyString)

	// If the resource is already in our map, then this is a modified event.  Check the
	// revision to see if we actually need to send an update.
	if revision, ok := ws.resourceRevisions[thisKeyString]; ok {
		if revision == thisRevision {
			// No update to revision, so no event to send.
			ws.logger.WithField("Key", thisKeyString).Debug("Swallowing event update from datastore because entry is same as cached entry")
			return
		}
		// Resource is modified, send an update event and store the latest revision.
		ws.logger.WithField("Key", thisKeyString).Debug("Datastore entry modified, sending syncer update")
		ws.syncerCallbacks.OnUpdates([]api.Update{{
			UpdateType: api.UpdateTypeKVUpdated,
			KVPair:     *kvp,
		}})
		ws.resourceRevisions[thisKeyString] = thisRevision
		return
	}

	// The resource has not been seen before, so send a new event, and store the
	// current revision.
	ws.logger.WithField("Key", thisKeyString).Debug("Cache entry added, sending syncer update")
	ws.syncerCallbacks.OnUpdates([]api.Update{{
		UpdateType: api.UpdateTypeKVNew,
		KVPair:     *kvp,
	}})
	ws.resourceRevisions[thisKeyString] = thisRevision
}

// handleDeletedWatchEvent sends a deleted event and removes the resource key from our cache.
func (ws *watcherSyncer) handleDeletedUpdate(key model.Key) {
	thisKeyString, err := model.KeyToDefaultPath(key)
	if err != nil {
		ws.logger.WithError(err).WithField("Key", key).Error("Unable to convert Key to string")
		return
	}
	ws.markAsValid(thisKeyString)

	// If we have seen an added event for this key then send a deleted event and remove
	// from the cache.
	if _, ok := ws.resourceRevisions[thisKeyString]; ok {
		ws.logger.WithField("Key", thisKeyString).Debug("Datastore entry deleted, sending syncer update")
		ws.syncerCallbacks.OnUpdates([]api.Update{{
			UpdateType: api.UpdateTypeKVDeleted,
			KVPair: model.KVPair{
				Key: key,
			},
		}})
		delete(ws.resourceRevisions, thisKeyString)
	}
}

// handleError checks the error type and for parse failures calls the ParseFailed.
func (ws *watcherSyncer) handleError(err error) {
	if pe, ok := err.(cerrors.ErrorParsingDatastoreEntry); ok {
		ws.logger.WithError(err).Info("Received parsing error")
		if pc, ok := ws.syncerCallbacks.(api.SyncerParseFailCallbacks); ok {
			pc.ParseFailed(pe.RawKey, pe.RawValue)
		}
	} else {
		ws.logger.WithError(err).Info("Received error in watcherSyncer - ignoring")
	}
}

// markAsValid marks a resource that we have just seen as valid, by moving it from the set of
// "oldResources" that were stored during the resync back into the main "resources" set.  Any entries
// remaining in the oldResources map once the current snapshot events have been processed, indicates
// entries that were deleted during the resync - see corresponding code in finishResync().
func (ws *watcherSyncer) markAsValid(resourceKey string) {
	if ws.oldResourceRevisions != nil {
		if oldResource, ok := ws.oldResourceRevisions[resourceKey]; ok {
			ws.logger.WithField("Key", resourceKey).Debug("Marking key as re-processed")
			ws.resourceRevisions[resourceKey] = oldResource
			delete(ws.oldResourceRevisions, resourceKey)
		}
	}
}
