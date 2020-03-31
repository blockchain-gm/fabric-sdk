/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kv

import (
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// NewFileKeyStore ...
func NewFileKeyStore(cryptoConfigMSPPath string) (KVStore, error) {
	opts := &FileKeyValueStoreOptions{
		Path: cryptoConfigMSPPath,
		KeySerializer: func(key interface{}) (string, error) {
			pkk, ok := key.(*PrivKeyKey)
			if !ok {
				return "", errors.New("converting key to PrivKeyKey failed")
			}
			if pkk == nil || pkk.MSPID == "" || pkk.ID == "" || pkk.SKI == nil {
				return "", errors.New("invalid key")
			}

			// TODO: refactor to case insensitive or remove eventually.
			r := strings.NewReplacer("{userName}", pkk.ID, "{username}", pkk.ID)
			keyDir := filepath.Join(r.Replace(cryptoConfigMSPPath), "keystore")

			return filepath.Join(keyDir, hex.EncodeToString(pkk.SKI)+"_sk"), nil
		},
	}
	return New(opts)
}
