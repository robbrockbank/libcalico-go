// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package etcdv3

import (
	"context"
	goerrors "errors"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/coreos/etcd/pkg/transport"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
)

var (
	clientTimeout = 30 * time.Second
)

type EtcdV3Client struct {
	etcdClient *clientv3.Client
}

func NewEtcdV3Client(config *apiconfig.EtcdConfig) (api.Client, error) {
	// Determine the location from the authority or the endpoints.  The endpoints
	// takes precedence if both are specified.
	etcdLocation := []string{}
	if config.EtcdEndpoints != "" {
		etcdLocation = strings.Split(config.EtcdEndpoints, ",")
	}

	if len(etcdLocation) == 0 {
		log.Info("No etcd endpoints specified in etcdv3 API config")
		return nil, goerrors.New("no etcd endpoints specified")
	}

	// Create the etcd client
	tlsInfo := &transport.TLSInfo{
		CAFile:   config.EtcdCACertFile,
		CertFile: config.EtcdCertFile,
		KeyFile:  config.EtcdKeyFile,
	}
	tls, _ := tlsInfo.ClientConfig()

	cfg := clientv3.Config{
		Endpoints:   etcdLocation,
		TLS:         tls,
		DialTimeout: clientTimeout,
	}

	// Plumb through the username and password if both are configured.
	if config.EtcdUsername != "" && config.EtcdPassword != "" {
		cfg.Username = config.EtcdUsername
		cfg.Password = config.EtcdPassword
	}

	client, err := clientv3.New(cfg)
	if err != nil {
		return nil, err
	}

	return &EtcdV3Client{etcdClient: client}, nil
}

// Create an entry in the datastore.  If the entry already exists, this will return
// an ErrorResourceAlreadyExists error and the current entry.
func (c *EtcdV3Client) Create(d *model.KVPair) (*model.KVPair, error) {
	logCxt := log.WithFields(log.Fields{"model-key": d.Key, "value": d.Value, "ttl": d.TTL, "rev": d.Revision})
	logCxt.Debug("Processing Create request")
	key, value, err := getKeyValueStrings(d)
	if err != nil {
		return nil, err
	}
	logCxt = logCxt.WithField("etcdv3-key", key)

	putOpts, err := c.getTTLOption(d)
	if err != nil {
		return nil, err
	}

	// Checking for 0 version of the key, which means it doesn't exists yet,
	// and if it does, get the current value.
	logCxt.Debug("Performing etcdv3 transaction for Create request")
	txnResp, err := c.etcdClient.Txn(context.Background()).If(
		clientv3.Compare(clientv3.Version(key), "=", 0),
	).Then(
		clientv3.OpPut(key, value, putOpts...),
	).Else(
		clientv3.OpGet(key),
	).Commit()
	if err != nil {
		logCxt.WithError(err).Warning("Create failed")
		return nil, errors.ErrorDatastoreError{Err: err}
	}

	if !txnResp.Succeeded {
		// The resource must already exist.  Extract the current value and
		// return that if possible.
		logCxt.Info("Create transaction failed due to resource already existing")
		var existing *model.KVPair
		getResp := (*clientv3.GetResponse)(txnResp.Responses[0].GetResponseRange())
		if len(getResp.Kvs) != 0 {
			if v, err := model.ParseValue(d.Key, getResp.Kvs[0].Value); err == nil {
				logCxt.Debug("Parsed existing entry to return in response")
				existing = &model.KVPair{
					Key:      d.Key,
					Value:    v,
					Revision: strconv.FormatInt(getResp.Kvs[0].ModRevision, 10),
				}
			}
		}
		return existing, errors.ErrorResourceAlreadyExists{Identifier: d.Key}
	}

	d.Revision = strconv.FormatInt(txnResp.Header.Revision, 10)

	return d, nil
}

// Update an entry in the datastore.  If the entry does not exist, this will return
// an ErrorResourceDoesNotExist error.  The ResourceVersion must be specified, and if
// incorrect will return a ErrorResourceUpdateConflict error and the current entry.
func (c *EtcdV3Client) Update(d *model.KVPair) (*model.KVPair, error) {
	logCxt := log.WithFields(log.Fields{"model-key": d.Key, "value": d.Value, "ttl": d.TTL, "rev": d.Revision})
	logCxt.Debug("Processing Update request")
	key, value, err := getKeyValueStrings(d)
	if err != nil {
		return nil, err
	}
	logCxt = logCxt.WithField("etcdv3-key", key)

	opts, err := c.getTTLOption(d)
	if err != nil {
		return nil, err
	}

	// ResourceVersion must be set for an Update.
	rev, err := strconv.ParseInt(d.Revision, 10, 64)
	if err != nil {
		logCxt.Info("Unable to parse Revision")
		return nil, err
	}
	conds := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(key), "=", rev)}

	logCxt.Debug("Performing etcdv3 transaction for Update request")
	txnResp, err := c.etcdClient.Txn(context.Background()).If(
		conds...,
	).Then(
		clientv3.OpPut(key, value, opts...),
	).Else(
		clientv3.OpGet(key),
	).Commit()

	if err != nil {
		logCxt.WithError(err).Warning("Update failed")
		return nil, errors.ErrorDatastoreError{Err: err}
	}

	// Etcd V3 does not return a error when compare condition fails we must verify the
	// response Succeeded field instead.  If the compare did not succeed then check for
	// a successful get to return either an UpdateConflict or a ResourceDoesNotExist error.
	if !txnResp.Succeeded {
		getResp := (*clientv3.GetResponse)(txnResp.Responses[0].GetResponseRange())
		if len(getResp.Kvs) == 0 {
			logCxt.Info("Update transaction failed due to resource not existing")
			return nil, errors.ErrorResourceDoesNotExist{Identifier: d.Key}
		}

		logCxt.Info("Update transaction failed due to resource update conflict")
		var existing *model.KVPair
		if v, err := model.ParseValue(d.Key, getResp.Kvs[0].Value); err == nil {
			logCxt.Debug("Parsed current entry to return in response")
			existing = &model.KVPair{
				Key:      d.Key,
				Value:    v,
				Revision: strconv.FormatInt(getResp.Kvs[0].ModRevision, 10),
			}
		}
		return existing, errors.ErrorResourceUpdateConflict{Identifier: d.Key}
	}

	d.Revision = strconv.FormatInt(txnResp.Header.Revision, 10)

	return d, nil
}

// Apply an existing entry in the datastore.  This ignores whether an entry already
// exists.
func (c *EtcdV3Client) Apply(d *model.KVPair) (*model.KVPair, error) {
	logCxt := log.WithFields(log.Fields{"key": d.Key, "value": d.Value, "ttl": d.TTL, "rev": d.Revision})
	logCxt.Debug("Processing Apply request")
	key, value, err := getKeyValueStrings(d)
	if err != nil {
		return nil, err
	}

	logCxt.Debug("Performing etcdv3 Put for Apply request")
	resp, err := c.etcdClient.Put(context.Background(), key, value)
	if err != nil {
		logCxt.WithError(err).Warning("Apply failed")
		return nil, errors.ErrorDatastoreError{Err: err}
	}

	d.Revision = strconv.FormatInt(resp.Header.Revision, 10)

	return d, nil
}

// Delete an entry in the datastore.  This errors if the entry does not exists.
func (c *EtcdV3Client) Delete(k model.Key, revision string) error {
	logCxt := log.WithFields(log.Fields{"model-key": k, "rev": revision})
	logCxt.Debug("Processing Delete request")
	key, err := model.KeyToDefaultDeletePath(k)
	if err != nil {
		return err
	}
	logCxt = logCxt.WithField("etcdv3-key", key)

	conds := []clientv3.Cmp{}
	if len(revision) != 0 {
		rev, err := strconv.ParseInt(revision, 10, 64)
		if err != nil {
			logCxt.Info("Unable to parse Revision")
			return err
		}
		conds = append(conds, clientv3.Compare(clientv3.ModRevision(key), "=", rev))
	}

	// Perform the delete transaction - note that this is an exact delete, not a prefix delete.
	logCxt.Debug("Performing etcdv3 transaction for Delete request")
	txnResp, err := c.etcdClient.Txn(context.Background()).If(
		conds...,
	).Then(
		clientv3.OpDelete(key),
	).Commit()
	if err != nil {
		logCxt.WithError(err).Warning("Delete failed")
		return errors.ErrorDatastoreError{Err: err, Identifier: k}
	}

	if !txnResp.Succeeded {
		logCxt.Info("Delete transaction failed due to resource update conflict")
		return errors.ErrorResourceUpdateConflict{Identifier: k}
	}

	delResp := txnResp.Responses[0].GetResponseDeleteRange()
	if delResp.Deleted == 0 {
		logCxt.Info("Delete transaction failed due resource not existing")
		return errors.ErrorResourceDoesNotExist{Identifier: k}
	}

	return nil
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *EtcdV3Client) Get(k model.Key, revision string) (*model.KVPair, error) {
	logCxt := log.WithFields(log.Fields{"model-key": k, "rev": revision})
	logCxt.Debug("Processing Get request")

	key, err := model.KeyToDefaultPath(k)
	if err != nil {
		logCxt.Error("Unable to convert model.Key to an etcdv3 key")
		return nil, err
	}
	logCxt = logCxt.WithField("etcdv3-key", key)

	ops := []clientv3.OpOption{}
	if len(revision) != 0 {
		rev, err := strconv.ParseInt(revision, 10, 64)
		if err != nil {
			logCxt.Error("Unable to parse Revision")
			return nil, err
		}
		ops = append(ops, clientv3.WithRev(rev))
	}

	logCxt.Debug("Calling Get on etcdv3 client")
	resp, err := c.etcdClient.Get(context.Background(), key, ops...)
	if err != nil {
		logCxt.WithError(err).Info("Error returned from etcdv3 client")
		return nil, errors.ErrorDatastoreError{Err: err}
	}
	if len(resp.Kvs) == 0 {
		logCxt.Info("No results returned from etcdv3 client")
		return nil, errors.ErrorResourceDoesNotExist{Identifier: k}
	}

	kv := resp.Kvs[0]
	v, err := model.ParseValue(k, kv.Value)
	if err != nil {
		logCxt.WithField("Value", string(kv.Value)).Error("Unable to parse Value")
		return nil, err
	}

	return &model.KVPair{
		Key:      k,
		Value:    v,
		Revision: strconv.FormatInt(kv.ModRevision, 10),
	}, nil
}

// List entries in the datastore.  This may return an empty list of there are
// no entries matching the request in the ListInterface.
func (c *EtcdV3Client) List(l model.ListInterface, revision string) (*model.KVPairList, error) {
	logCxt := log.WithFields(log.Fields{"list-interface": l, "rev": revision})
	logCxt.Debug("Processing List request")

	// To list entries, we enumerate from the common root based on the supplied
	// IDs, and then filter the results.
	key := model.ListOptionsToDefaultPathRoot(l)

	// If the key is actually fully qualified, then do not perform a prefix Get.
	// If the key is just a prefix, then append a terminating "/" and perform a prefix Get.
	// The terminating / for a prefix Get ensures for a prefix of "/a" we only return "child entries"
	// of "/a" such as "/a/x" and not siblings such as "/ab".
	ops := []clientv3.OpOption{}
	if l.KeyFromDefaultPath(key) == nil {
		// The key not a fully qualified key - it must be a prefix.
		logCxt.Info("Performing a prefix query")
		if !strings.HasSuffix(key, "/") {
			key += "/"
		}
		ops = append(ops, clientv3.WithPrefix())
	}
	logCxt = logCxt.WithField("etcdv3-key", key)

	// We may also need to perform a get based on a particular revision.
	if len(revision) != 0 {
		rev, err := strconv.ParseInt(revision, 10, 64)
		if err != nil {
			logCxt.Error("Unable to parse Revision")
			return nil, err
		}
		ops = append(ops, clientv3.WithRev(rev))
	}

	logCxt.Debug("Calling Get on etcdv3 client")
	resp, err := c.etcdClient.Get(context.Background(), key, ops...)
	if err != nil {
		logCxt.WithError(err).Info("Error returned from etcdv3 client")
		return nil, errors.ErrorDatastoreError{Err: err}
	}
	logCxt.WithField("numResults", len(resp.Kvs)).Debug("Processing response from etcdv3")

	list := filterEtcdV3List(resp.Kvs, l)
	return &model.KVPairList{
		KVPairs:  list,
		Revision: strconv.FormatInt(resp.Header.Revision, 10),
	}, nil
}

// EnsureInitialized makes sure that the etcd data is initialized for use by
// Calico.
func (c *EtcdV3Client) EnsureInitialized() error {
	// Make sure the Ready flag is initialized in the datastore
	kv := &model.KVPair{
		Key:   model.ReadyFlagKey{},
		Value: true,
	}

	if _, err := c.Create(kv); err != nil {
		if _, ok := err.(errors.ErrorResourceAlreadyExists); !ok {
			log.WithError(err).Warn("Failed to set ready flag")
			return err
		}
	}

	log.Info("Ready flag is already set")
	return nil
}

// Clean removes all of the Calico data from the datastore.
func (c *EtcdV3Client) Clean() error {
	log.Warning("Cleaning etcdv3 datastore of all Calico data")
	_, err := c.etcdClient.Txn(context.Background()).If().Then(
		clientv3.OpDelete("/calico", clientv3.WithPrefix()),
	).Commit()

	if err != nil {
		return errors.ErrorDatastoreError{Err: err}
	}
	return nil
}

// Syncer returns a v1 Syncer used to stream resource updates.
func (c *EtcdV3Client) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	return newSyncerV3(c.etcdClient, callbacks)
}

// Process a node returned from a list to filter results based on the List type and to
// compile and return the required results.
func filterEtcdV3List(pairs []*mvccpb.KeyValue, l model.ListInterface) []*model.KVPair {
	kvs := []*model.KVPair{}
	for _, p := range pairs {
		log.WithField("etcdv3-key", p.Key).Debug("Processing etcdv3 entry")
		if k := l.KeyFromDefaultPath(string(p.Key)); k != nil {
			log.WithField("model-key", k).Debugf("Key is valid and converted to model-key")
			if v, err := model.ParseValue(k, p.Value); err == nil {
				log.Debug("Value is valid - filter value into list")
				kv := &model.KVPair{Key: k, Value: v, Revision: strconv.FormatInt(p.ModRevision, 10)}
				kvs = append(kvs, kv)
			}
		}
	}

	log.Debugf("Returning filtered list: %#v", kvs)
	return kvs
}

// getTTLOption returns a OpOption slice containing a Lease granted for the TTL.
func (c *EtcdV3Client) getTTLOption(d *model.KVPair) ([]clientv3.OpOption, error) {
	putOpts := []clientv3.OpOption{}

	if d.TTL != 0 {
		resp, err := c.etcdClient.Lease.Grant(context.Background(), int64(d.TTL.Seconds()))
		if err != nil {
			log.WithError(err).Error("Failed to grant a lease")
			return nil, errors.ErrorDatastoreError{Err: err}
		}

		putOpts = append(putOpts, clientv3.WithLease(resp.ID))
	}

	return putOpts, nil
}

// getKeyValueStrings returns the etcdv3 key and serialized value calculated from the
// KVPair.
func getKeyValueStrings(d *model.KVPair) (string, string, error) {
	logCxt := log.WithFields(log.Fields{"model-key": d.Key, "value": d.Value})
	key, err := model.KeyToDefaultPath(d.Key)
	if err != nil {
		logCxt.WithError(err).Error("Failed to convert model-key to etcdv3 key")
		return "", "", err
	}
	bytes, err := model.SerializeValue(d)
	if err != nil {
		logCxt.WithError(err).Error("Failed to serialize value")
		return "", "", err
	}

	return key, string(bytes), nil
}
