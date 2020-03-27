/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package x509

import (
	"encoding/hex"
	"net/http"

	"fabric-sdk/bccsp"
	// "fabric-sdk/core"

	factory "fabric-sdk/fabric-ca/sdkpatch/cryptosuitebridge"

	log "fabric-sdk/fabric-ca/sdkpatch/logbridge"

	"fabric-sdk/fabric-ca/api"
	"fabric-sdk/fabric-ca/lib/client/credential"

	"fabric-sdk/fabric-ca/util"

	// "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/pkg/errors"
)

const (
	// CredType is the string that represents X509 credential type
	CredType = "X509"
)

// Client represents a client that will load/store an Idemix credential
type Client interface {
	NewX509Identity(name string, creds []credential.Credential) Identity
	GetCSP() bccsp.BCCSP
}

// Identity represents an identity
type Identity interface {
	Revoke(req *api.RevocationRequest) (*api.RevocationResponse, error)
}

// Credential represents a X509 credential. Implements Credential interface
type Credential struct {
	client   Client
	certFile []byte
	keyFile  bccsp.Key
	val      *Signer
}

// NewCredential is constructor for X509 Credential
func NewCredential(keyFile bccsp.Key, certFile []byte, c Client) *Credential {
	return &Credential{
		c, certFile, keyFile, nil,
	}
}

// Type returns X509
func (cred *Credential) Type() string {
	return CredType
}

// Val returns *Signer associated with this X509 credential
func (cred *Credential) Val() (interface{}, error) {
	if cred.val == nil {
		return nil, errors.New("X509 Credential value is not set")
	}
	return cred.val, nil
}

// EnrollmentID returns enrollment ID of this X509 credential
func (cred *Credential) EnrollmentID() (string, error) {
	if cred.val == nil {
		return "", errors.New("X509 Credential value is not set")
	}
	return cred.val.GetName(), nil
}

// SetVal sets *Signer for this X509 credential
func (cred *Credential) SetVal(val interface{}) error {
	s, ok := val.(*Signer)
	if !ok {
		return errors.New("The X509 credential value must be of type *Signer for X509 credential")
	}
	cred.val = s
	return nil
}

// Load loads the certificate and key from the location specified by
// certFile attribute using the BCCSP of the client. The private key is
// loaded from the location specified by the keyFile attribute, if the
// private key is not found in the keystore managed by BCCSP
func (cred *Credential) Load() error {
	var err error
	cred.val, err = NewSigner(cred.keyFile, cred.certFile)
	if err != nil {
		return err
	}
	return nil
}

// Store stores the certificate associated with this X509 credential to the location
// specified by certFile attribute
func (cred *Credential) Store() error {
	log.Debugf("Credential.Store() not supported")
	return nil
}

// CreateToken creates token based on this X509 credential
func (cred *Credential) CreateToken(req *http.Request, reqBody []byte, fabCACompatibilityMode bool) (string, error) {
	return util.CreateToken(cred.getCSP(), cred.val.certBytes, cred.val.key, req.Method, req.URL.RequestURI(), reqBody, fabCACompatibilityMode)
}

// RevokeSelf revokes this X509 credential
func (cred *Credential) RevokeSelf() (*api.RevocationResponse, error) {
	name, err := cred.EnrollmentID()
	if err != nil {
		return nil, err
	}
	val := cred.val
	serial := util.GetSerialAsHex(val.cert.SerialNumber)
	aki := hex.EncodeToString(val.cert.AuthorityKeyId)
	req := &api.RevocationRequest{
		Serial: serial,
		AKI:    aki,
	}

	id := cred.client.NewX509Identity(name, []credential.Credential{cred})
	return id.Revoke(req)
}

func (cred *Credential) getCSP() bccsp.BCCSP {
	if cred.client != nil && cred.client.GetCSP() != nil {
		return cred.client.GetCSP()
	}
	return factory.GetDefault()
}
