/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"path/filepath"
	// "strings"

	"fabric-sdk/bccsp"
	"fabric-sdk/kv"

	"github.com/pkg/errors"
	// "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	// "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	// "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
)

type CertKeyPair struct {
	Cert []byte
	Key  []byte
}

// IdentityManager implements fab/IdentityManager
type IdentityManager struct {
	orgName  string
	orgMSPID string
	// config          fab.EndpointConfig
	cryptoSuite     bccsp.BCCSP
	embeddedUsers   map[string]CertKeyPair
	mspPrivKeyStore kv.KVStore
	mspCertStore    kv.KVStore
	userStore       kv.UserStore
}

// NewIdentityManager creates a new instance of IdentityManager
func NewIdentityManager(orgName, mspID string, users map[string]CertKeyPair, cryptoPath string, userStore kv.UserStore, cryptoSuite bccsp.BCCSP, cryptoConfigPath string) (*IdentityManager, error) {

	// netConfig := endpointConfig.NetworkConfig()
	// // viper keys are case insensitive
	// orgConfig, ok := netConfig.Organizations[strings.ToLower(orgName)]
	// if !ok {
	// 	return nil, errors.New("org config retrieval failed")
	// }

	// if orgConfig.CryptoPath == "" && len(orgConfig.Users) == 0 {
	// 	return nil, errors.New("Either a cryptopath or an embedded list of users is required")
	// }

	var mspPrivKeyStore kv.KVStore
	var mspCertStore kv.KVStore

	orgCryptoPathTemplate := cryptoPath
	if orgCryptoPathTemplate != "" {
		var err error
		if !filepath.IsAbs(orgCryptoPathTemplate) {
			orgCryptoPathTemplate = filepath.Join(cryptoConfigPath, orgCryptoPathTemplate)
		}
		mspPrivKeyStore, err = kv.NewFileKeyStore(orgCryptoPathTemplate)
		if err != nil {
			return nil, errors.Wrap(err, "creating a private key store failed")
		}
		mspCertStore, err = kv.NewFileCertStore(orgCryptoPathTemplate)
		if err != nil {
			return nil, errors.Wrap(err, "creating a cert store failed")
		}
	}
	//  else {
	// 	logger.Warnf("Cryptopath not provided for organization [%s], MSP stores not created", orgName)
	// }

	mgr := &IdentityManager{
		orgName:  orgName,
		orgMSPID: mspID,
		// config:          endpointConfig,
		cryptoSuite:     cryptoSuite,
		mspPrivKeyStore: mspPrivKeyStore,
		mspCertStore:    mspCertStore,
		embeddedUsers:   users,
		userStore:       userStore,
		// CA Client state is created lazily, when (if) needed
	}
	return mgr, nil
}
