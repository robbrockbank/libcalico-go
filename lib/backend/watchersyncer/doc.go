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
watchersyncer package contains a syncer interface that can be used to sync from an
arbitrary Watcher.

An optional processor may be specified for each watch type that convert between the
raw data returned by the watch and the updates returned by the syncer.

The implementation could easily be ported to work on the main client Watcher which
would be the preferred approach once all of the entries that we need to watch are
defined as resource types.

This can be used in conjunction with the multisyncer that
*/
package watchersyncer
