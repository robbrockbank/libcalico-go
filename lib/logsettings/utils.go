// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package logsetting

import (
	"context"
	"reflect"
	"time"

	v3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	log "github.com/sirupsen/logrus"
	"k8s.io/klog"
)

const (
	sleepTime = 10 * time.Second
)

var (
	previouslySet = false
)

type updateHandler func(logLevel v3.LogLevel, any interface{})

// DefaultHandler sets log level to Debug if DebuggingConfiguration log setting is set to v3.LogLevelDebug
// Set it to Info otherwise.
// This method can be used by any process which has no other mechanism of setting log level and for which then
// DebuggingConfiguration is the only mechanism.
// Goal is to eventually deprecate any other mechanism and leave DebuggingConfiguration is the only mechanism.
func DefaultHandler(logLevel v3.LogLevel, any interface{}) {
	if logLevel == v3.LogLevelDebug {
		klog.Info("DefaultHandler set log level to Debug")
		log.SetLevel(log.DebugLevel)
		return
	}
	klog.Info("DefaultHandler set log level to Info")
	log.SetLevel(log.InfoLevel)
}

// checkAndEnforceConfiguration get default DebuggingConfiguration. There are two possible configuration for the component:
// - component+node
// - component
// Most specific wins. If set, calls registerd method with corresponding values.
// If not set call registered method with LogLevelNotSet.
func checkAndEnforceConfiguration(dc *v3.DebuggingConfiguration, component v3.Component,
	node string, f updateHandler, any interface{}) {
	logLevel := v3.LogLevelNotSet

	if dc != nil {
		configuration := dc.Spec.Configuration
		for _, c := range configuration {
			if component == c.Component && node == c.Node {
				// If both component and node matches, this is highest priority.
				// Use corresponding log severity and break the loop.
				logLevel = c.LogSeverity
				break
			} else if component == c.Component && c.Node == "" {
				// If component matches and node is not set, save corresponding log
				// severity but DO NOT break the loop. It is possible there is another
				// entry with matching component and node. That has higher priority.
				logLevel = c.LogSeverity
			}
		}
	}

	// Only reacts to change if log level configuration is present or it was present
	// before but it is not set anymore
	if logLevel != v3.LogLevelNotSet {
		previouslySet = true
		f(logLevel, any)
	} else if previouslySet {
		previouslySet = false
		f(logLevel, any)
	}
}

func getDebuggingConfiguration(ctx context.Context, debuggingConfigurationClient clientv3.DebuggingConfigurationInterface) (*v3.DebuggingConfiguration, error) {

	dc, err := debuggingConfigurationClient.Get(ctx, "default", options.GetOptions{})
	if err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
			log.Info("default DebuggingConfiguration does not exist.")
			return nil, nil
		} else {
			log.Info("Failed to get default DebuggingConfiguration: ", err)
			return nil, err
		}
	}

	return dc, nil
}

func startWatcher(ctx context.Context, c client.Interface, component v3.Component, node string, f updateHandler, any interface{}) {
	debuggingConfigurationClient := c.DebuggingConfiguration()

MAINLOOP:
	for {
		// Watch for
		w, err := debuggingConfigurationClient.Watch(ctx, options.ListOptions{Name: "default"})
		if err != nil {
			// Watch failed
			log.WithError(err).Warn("unable to watch DebuggingConfiguration")
			time.Sleep(sleepTime)
			continue MAINLOOP
		}
		defer w.Stop()
		for e := range w.ResultChan() {

			select {
			case <-ctx.Done():
				return
			default:
				// no-op
			}

			switch e.Type {
			case watch.Error:
				log.Debug("DebuggingConfiguration watch got Error")
				// Handle a WatchError.  First determine if the error type indicates that the
				// watch has closed, and if so we'll need to resync and create a new watcher.
				if e, ok := e.Error.(errors.ErrorWatchTerminated); ok {
					log.Debug("Received watch terminated error - recreate watcher")
					if !e.ClosedByRemote {
						// If the watcher was not closed by remote, trigger a full resync
						// rather than simply trying to watch from the last event revision.
						log.Debug("Watch was not closed by remote - full resync required")
						time.Sleep(sleepTime)
						dc, _ := getDebuggingConfiguration(ctx, debuggingConfigurationClient)
						checkAndEnforceConfiguration(dc, component, node, f, any)
					}
				} else {
					// Some other watch error; restart from beginning
					log.WithError(err).Error("error watching DebuggingConfiguration")
					time.Sleep(sleepTime)
					dc, _ := getDebuggingConfiguration(ctx, debuggingConfigurationClient)
					checkAndEnforceConfiguration(dc, component, node, f, any)
				}
				continue MAINLOOP
			case watch.Added:
				log.Debug("DebuggingConfiguration watch got Add")
				newDC := e.Object.(*v3.DebuggingConfiguration)
				if newDC.Name != "default" {
					// Ignore it. It should never happen. Validation in libcalico prevents this.
					log.WithField("name", newDC.Name).Warning("unexpected DebuggingConfiguration object")
					continue
				}
				checkAndEnforceConfiguration(newDC, component, node, f, any)
			case watch.Modified:
				log.Debug("DebuggingConfiguration watch got Modify")
				newDC := e.Object.(*v3.DebuggingConfiguration)
				doProcessUpdate := true
				if e.Previous != nil {
					oldDC := e.Previous.(*v3.DebuggingConfiguration)
					if reflect.DeepEqual(newDC.Spec.Configuration, oldDC.Spec.Configuration) {
						doProcessUpdate = false
					}
				}
				if doProcessUpdate && newDC.Name != "default" {
					// Ignore it. It should never happen. Validation in libcalico prevents this.
					log.WithField("name", newDC.Name).Warning("unexpected DebuggingConfiguration object")
					continue
				}
				checkAndEnforceConfiguration(newDC, component, node, f, any)
			case watch.Deleted:
				log.Debug("DebuggingConfiguration watch got Deleted")
				checkAndEnforceConfiguration(nil, component, node, f, any)
			}
		}
	}
}

// RegisterForLogSettings registers f to be invoked any time DebuggingConfiguration change.
// Pod service account must have permission to read DebuggingConfiguration.
// DebuggingConfiguration is the custom resource to be used to uniformly set log level for all calico component.
// By calling this method, any change in DebuggingConfiguration.Spec will be processed and registered method f
// will be invoked any time configuration for log severity for such component is modified.
// When invoked, f(logSeverity, any) where logSeverity is the value specified in the DebuggingConfiguration default
// instance for component (eventually running on node if specified at registration time).
// any can be nil. It is simply used to allow passing an extra argument to f.
func RegisterForLogSettings(ctx context.Context, c client.Interface, component v3.Component, node string,
	f updateHandler, any interface{}) {
	log.Infof("RegisterForLogSettings component: %s node: %s", component, node)

	// Do not move inside go routine. Make sure proper debugging level is set
	// before watcher is started and registration returns
	debuggingConfigurationClient := c.DebuggingConfiguration()
	dc, err := getDebuggingConfiguration(ctx, debuggingConfigurationClient)
	if err != nil {
		// Cannot get DebuggingConfiguration. Do nothing.
		// TODO: should we retry?
	}

	checkAndEnforceConfiguration(dc, component, node, f, any)

	go startWatcher(ctx, c, component, node, f, any)
}
