/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kv

import (
	"fmt"
	"path/filepath"
	"strings"

	// "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	// "github.com/hyperledger/fabric-sdk-go/pkg/fab/keyvaluestore"
	"github.com/pkg/errors"
)

// NewFileCertStore ...
func NewFileCertStore(cryptoConfigMSPPath string) (KVStore, error) {
	_, orgName := filepath.Split(filepath.Dir(filepath.Dir(filepath.Dir(cryptoConfigMSPPath))))
	opts := &FileKeyValueStoreOptions{
		Path: cryptoConfigMSPPath,
		KeySerializer: func(key interface{}) (string, error) {
			ck, ok := key.(*IdentityIdentifier)
			if !ok {
				return "", errors.New("converting key to CertKey failed")
			}
			if ck == nil || ck.MSPID == "" || ck.ID == "" {
				return "", errors.New("invalid key")
			}

			// TODO: refactor to case insensitive or remove eventually.
			r := strings.NewReplacer("{userName}", ck.ID, "{username}", ck.ID)
			certDir := filepath.Join(r.Replace(cryptoConfigMSPPath), "signcerts")
			return filepath.Join(certDir, fmt.Sprintf("%s@%s-cert.pem", ck.ID, orgName)), nil
		},
	}
	return New(opts)
}
