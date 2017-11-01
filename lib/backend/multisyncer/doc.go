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

/*
Package multisyncer implements a syncer comprised of multiple syncers.

Each sub-syncer is assumed to only go in a forward-sync-state direction, i.e.
  WaitForDatastore -> ResyncInProgress -> InSync

The multi syncer buffers the results from each sub-syncer and passes the events
through to the main syncer client.  The state of the multi syncer starts moves
to ResyncInProgress when the first sub-syncer indicates a ResyncInProgress, and moves
to InSync when *all* sub-syncers have reported InSync.

It is the responsibility of each sub-syncer to maintain sufficient state that it
can handles it's own under-the-cover resyncing as required for transient datastore
errors.
*/
package multisyncer
