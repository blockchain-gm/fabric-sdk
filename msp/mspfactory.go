package msp

import (
	"fmt"

	// "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	// "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	// "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	// "github.com/hyperledger/fabric-sdk-go/pkg/fabsdk/provider/msppvdr"
	// mspimpl "github.com/hyperledger/fabric-sdk-go/pkg/msp"
	"fabric-sdk/kv"

	"github.com/pkg/errors"
)

// ProviderFactory represents the default MSP provider factory.
type ProviderFactory struct {
}

// NewProviderFactory returns the default MSP provider factory.
func NewProviderFactory() *ProviderFactory {
	f := ProviderFactory{}
	return &f
}

// CreateUserStore creates a UserStore using the SDK's default implementation
func (f *ProviderFactory) CreateUserStore(stateStorePath string) (*kv.UserStore, error) {
	var userStore *kv.UserStore

	if stateStorePath == "" {
		return nil, fmt.Errorf("%s", "stateStorePath not exist")
	} else {
		stateStore, err := kv.New(&kv.FileKeyValueStoreOptions{Path: stateStorePath})
		if err != nil {
			return nil, errors.WithMessage(err, "CreateNewFileKeyValueStore failed")
		}
		userStore, err = NewCertFileUserStore1(stateStore)
		if err != nil {
			return nil, errors.Wrapf(err, "creating a user store failed")
		}
	}

	return userStore, nil
}

// // CreateIdentityManagerProvider returns a new default implementation of MSP provider
// func (f *ProviderFactory) CreateIdentityManagerProvider(endpointConfig fab.EndpointConfig, cryptoProvider core.CryptoSuite, userStore msp.UserStore) (msp.IdentityManagerProvider, error) {
// 	return msppvdr.New(endpointConfig, cryptoProvider, userStore)
// }
