/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"encoding/hex"
	"fabric-sdk/bccsp"
	"fabric-sdk/fabric-ca/util"
	"fabric-sdk/kv"
	"fmt"
	"strings"

	// fabricCaUtil "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/util"
	// "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	// "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	// "github.com/hyperledger/fabric-sdk-go/pkg/core/config/cryptoutil"
	// "github.com/hyperledger/fabric-sdk-go/pkg/fab/comm"
	"github.com/pkg/errors"
)

type User struct {
	id                    string
	mspID                 string
	enrollmentCertificate []byte
	privateKey            bccsp.Key
}

func newUser(userData *kv.UserData, cryptoSuite bccsp.BCCSP) (*User, error) {
	pubKey, err := GetPublicKeyFromCert(userData.EnrollmentCertificate, cryptoSuite)
	if err != nil {
		return nil, errors.WithMessage(err, "fetching public key from cert failed")
	}
	pk, err := cryptoSuite.GetKey(pubKey.SKI())
	if err != nil {
		return nil, errors.WithMessage(err, "cryptoSuite GetKey failed")
	}
	u := &User{
		id:                    userData.ID,
		mspID:                 userData.MSPID,
		enrollmentCertificate: userData.EnrollmentCertificate,
		privateKey:            pk,
	}
	return u, nil
}

// NewUser creates a User instance
func (mgr *IdentityManager) NewUser(userData *kv.UserData) (*User, error) {
	return newUser(userData, mgr.cryptoSuite)
}

func (mgr *IdentityManager) loadUserFromStore(username string) (*User, error) {
	if mgr.userStore == nil {
		return nil, ErrUserNotFound
	}
	var user *User
	userData, err := mgr.userStore.Load(kv.IdentityIdentifier{MSPID: mgr.orgMSPID, ID: username})
	if err != nil {
		return nil, err
	}
	user, err = mgr.NewUser(userData)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetSigningIdentity returns a signing identity for the given id
func (mgr *IdentityManager) GetSigningIdentity(id string) (*User, error) {
	user, err := mgr.GetUser(id)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// CreateSigningIdentity creates a signing identity with the given options
func (mgr *IdentityManager) CreateSigningIdentity(opts ...SigningIdentityOption) (*User, error) {
	opt := IdentityOption{}
	for _, param := range opts {
		err := param(&opt)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to create identity")
		}
	}
	if opt.Cert == nil {
		return nil, errors.New("missing certificate")
	}
	var privateKey bccsp.Key
	if opt.PrivateKey == nil {
		pubKey, err := GetPublicKeyFromCert(opt.Cert, mgr.cryptoSuite)
		if err != nil {
			return nil, errors.WithMessage(err, "fetching public key from cert failed")
		}
		privateKey, err = mgr.cryptoSuite.GetKey(pubKey.SKI())
		if err != nil {
			return nil, errors.WithMessage(err, "could not find matching key for SKI")
		}
	} else {
		var err error
		privateKey, err = util.ImportBCCSPKeyFromPEMBytes(opt.PrivateKey, mgr.cryptoSuite, true)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to import key")
		}
	}
	return &User{
		mspID:                 mgr.orgMSPID,
		enrollmentCertificate: opt.Cert,
		privateKey:            privateKey,
	}, nil
}

// GetUser returns a user for the given user name
func (mgr *IdentityManager) GetUser(username string) (*User, error) { //nolint
	u, err := mgr.loadUserFromStore(username)
	if err != nil {
		if err != ErrUserNotFound {
			return nil, errors.WithMessage(err, "loading user from store failed")
		}
		// Not found, continue
	}

	if u == nil {
		certBytes := mgr.getEmbeddedCertBytes(username)
		if certBytes == nil {
			certBytes, err = mgr.getCertBytesFromCertStore(username)
			if err != nil && err != ErrUserNotFound {
				return nil, errors.WithMessage(err, "fetching cert from store failed")
			}
		}
		if certBytes == nil {
			return nil, ErrUserNotFound
		}
		privateKey, err := mgr.getEmbeddedPrivateKey(username)
		if err != nil {
			return nil, errors.WithMessage(err, "fetching embedded private key failed")
		}
		if privateKey == nil {
			privateKey, err = mgr.getPrivateKeyFromCert(username, certBytes)
			if err != nil {
				return nil, errors.WithMessage(err, "getting private key from cert failed")
			}
		}
		if privateKey == nil {
			return nil, fmt.Errorf("unable to find private key for user [%s]", username)
		}
		// mspID, ok := comm.MSPID(mgr.config, mgr.orgName)
		// if !ok {
		// 	return nil, errors.New("MSP ID config read failed")
		// }
		u = &User{
			id:                    username,
			mspID:                 mgr.orgMSPID,
			enrollmentCertificate: certBytes,
			privateKey:            privateKey,
		}
	}
	return u, nil
}

func (mgr *IdentityManager) GetUserPriKey(username string) ([]byte, string, error) { //nolint
	u, err := mgr.loadUserFromStore(username)
	if err != nil {
		if err != ErrUserNotFound {
			return nil, "", errors.WithMessage(err, "loading user from store failed")
		}
		return nil, "", err
	}

	privateKey, err := mgr.getPriKeyBytesFromKeyStore(username, u.privateKey.SKI())
	if err != nil {
		return nil, "", errors.WithMessage(err, "getting private key from cert failed")
	}
	return privateKey, hex.EncodeToString(u.privateKey.SKI()) + "_sk", nil
}

func (mgr *IdentityManager) getEmbeddedCertBytes(username string) []byte {
	return mgr.embeddedUsers[strings.ToLower(username)].Cert
}

func (mgr *IdentityManager) getEmbeddedPrivateKey(username string) (bccsp.Key, error) {
	var privateKey bccsp.Key
	var err error
	pemBytes := mgr.embeddedUsers[strings.ToLower(username)].Key
	if pemBytes != nil {
		// Try the crypto provider as a SKI
		privateKey, err = mgr.cryptoSuite.GetKey(pemBytes)
		if err != nil || privateKey == nil {
			// Try as a pem
			privateKey, err = util.ImportBCCSPKeyFromPEMBytes(pemBytes, mgr.cryptoSuite, true)
			if err != nil {
				return nil, errors.Wrap(err, "import private key failed")
			}
		}
	}

	return privateKey, nil
}

func (mgr *IdentityManager) getPrivateKeyPemFromKeyStore(username string, ski []byte) ([]byte, error) {
	if mgr.mspPrivKeyStore == nil {
		return nil, nil
	}
	key, err := mgr.mspPrivKeyStore.Load(
		&kv.PrivKeyKey{
			ID:    username,
			MSPID: mgr.orgMSPID,
			SKI:   ski,
		})
	if err != nil {
		return nil, err
	}
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, errors.New("key from store is not []byte")
	}
	return keyBytes, nil
}

func (mgr *IdentityManager) getCertBytesFromCertStore(username string) ([]byte, error) {
	if mgr.mspCertStore == nil {
		return nil, ErrUserNotFound
	}
	cert, err := mgr.mspCertStore.Load(&kv.IdentityIdentifier{
		ID:    username,
		MSPID: mgr.orgMSPID,
	})
	if err != nil {
		if err == kv.ErrKeyValueNotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	certBytes, ok := cert.([]byte)
	if !ok {
		return nil, errors.New("cert from store is not []byte")
	}
	return certBytes, nil
}

func (mgr *IdentityManager) getPrivateKeyFromCert(username string, cert []byte) (bccsp.Key, error) {
	if cert == nil {
		return nil, errors.New("cert is nil")
	}
	pubKey, err := GetPublicKeyFromCert(cert, mgr.cryptoSuite)
	if err != nil {
		return nil, errors.WithMessage(err, "fetching public key from cert failed")
	}
	privKey, err := mgr.getPrivateKeyFromKeyStore(username, pubKey.SKI())
	if err == nil {
		return privKey, nil
	}
	if err != kv.ErrKeyValueNotFound {
		return nil, errors.WithMessage(err, "fetching private key from key store failed")
	}
	return mgr.cryptoSuite.GetKey(pubKey.SKI())
}

func (mgr *IdentityManager) getPrivateKeyFromKeyStore(username string, ski []byte) (bccsp.Key, error) {
	pemBytes, err := mgr.getPrivateKeyPemFromKeyStore(username, ski)
	if err != nil {
		return nil, err
	}
	if pemBytes != nil {
		return util.ImportBCCSPKeyFromPEMBytes(pemBytes, mgr.cryptoSuite, true)
	}
	return nil, kv.ErrKeyValueNotFound
}

//add new func
func (mgr *IdentityManager) getPriKeyBytesFromKeyStore(username string, ski []byte) ([]byte, error) {
	pemBytes, err := mgr.getPrivateKeyPemFromKeyStore(username, ski)
	if err != nil {
		return nil, err
	}
	if pemBytes == nil {
		return nil, kv.ErrKeyValueNotFound
	}
	return pemBytes, nil
}

//add new func
func (mgr *IdentityManager) getPriKeyBytesFromCert(username string, cert []byte) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("cert is nil")
	}
	pubKey, err := GetPublicKeyFromCert(cert, mgr.cryptoSuite)
	if err != nil {
		return nil, errors.WithMessage(err, "fetching public key from cert failed")
	}
	return mgr.getPriKeyBytesFromKeyStore(username, pubKey.SKI())
}
