package msp

import (
	// "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	// "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	// "github.com/hyperledger/fabric-sdk-go/pkg/fab/keyvaluestore"
	"fabric-sdk/kv"

	"github.com/pkg/errors"
)

var (
	// ErrUserNotFound indicates the user was not found
	ErrUserNotFound = errors.New("user not found")
)

// CertFileUserStore stores each user in a separate file.
// Only user's enrollment cert is stored, in pem format.
// File naming is <user>@<org>-cert.pem
type CertFileUserStore struct {
	store kv.KVStore
}

func storeKeyFromUserIdentifier(key kv.IdentityIdentifier) string {
	return key.ID + "@" + key.MSPID + "-cert.pem"
}

// NewCertFileUserStore1 creates a new instance of CertFileUserStore
func NewCertFileUserStore1(store FileKeyValueStore) (*CertFileUserStore, error) {
	return &FileKeyValueStore{
		store: store,
	}, nil
}

// NewCertFileUserStore creates a new instance of CertFileUserStore
func NewCertFileUserStore(path string) (*CertFileUserStore, error) {
	if path == "" {
		return nil, errors.New("path is empty")
	}
	store, err := kv.New(&FileKeyValueStoreOptions{
		Path: path,
	})
	if err != nil {
		return nil, errors.WithMessage(err, "user store creation failed")
	}
	return NewCertFileUserStore1(store)
}

// Load returns the User stored in the store for a key.
func (s *CertFileUserStore) Load(key IdentityIdentifier) (*kv.UserData, error) {
	cert, err := s.store.Load(storeKeyFromUserIdentifier(key))
	if err != nil {
		if err == ErrKeyValueNotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	certBytes, ok := cert.([]byte)
	if !ok {
		return nil, errors.New("user is not of proper type")
	}
	userData := &UserData{
		MSPID:                 key.MSPID,
		ID:                    key.ID,
		EnrollmentCertificate: certBytes,
	}
	return userData, nil
}

// Store stores a User into store
func (s *CertFileUserStore) Store(user *kv.UserData) error {
	key := storeKeyFromUserIdentifier(kv.IdentityIdentifier{MSPID: user.MSPID, ID: user.ID})
	return s.store.Store(key, user.EnrollmentCertificate)
}

// Delete deletes a User from store
func (s *CertFileUserStore) Delete(key IdentityIdentifier) error {
	return s.store.Delete(storeKeyFromUserIdentifier(key))
}
