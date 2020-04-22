package libfab

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"

	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/tjfoc/gmsm/sm2"
)

type CryptoConfig struct {
	MSPID      string   `json:"name"`
	PrivKey    string   `json:"private_key"`
	SignCert   string   `json:"sign_cert"`
	TLSCACerts []string `json:"tls_ca_cert"`
}

type ECDSASignature struct {
	R, S *big.Int
}

type Crypto struct {
	Creator []byte
	// PrivKey    *ecdsa.PrivateKey
	PrivKey    interface{}
	SignCert   *x509.Certificate
	TLSCACerts [][]byte
}

func (s *Crypto) Sign(message []byte) ([]byte, error) {
	var (
		ecdsaPriKey *ecdsa.PrivateKey
		sm2PriKey   *sm2.PrivateKey
	)
	switch s.PrivKey.(type) {
	case *ecdsa.PrivateKey:
		ecdsaPriKey = s.PrivKey.(*ecdsa.PrivateKey)
		ri, si, err := ecdsa.Sign(rand.Reader, ecdsaPriKey, digest(message))
		if err != nil {
			return nil, err
		}

		si, _, err = utils.ToLowS(&ecdsaPriKey.PublicKey, si)
		if err != nil {
			return nil, err
		}

		return asn1.Marshal(ECDSASignature{ri, si})
	case *sm2.PrivateKey:
		fmt.Println("sm2 PrivateKey sign")
		sm2PriKey = s.PrivKey.(*sm2.PrivateKey)
		return sm2PriKey.Sign(rand.Reader, digest(message), nil)
	}
	return nil, fmt.Errorf("%s", "unknow private key type.")
}

func (s *Crypto) Serialize() ([]byte, error) {
	return s.Creator, nil
}

func (s *Crypto) NewSignatureHeader() (*common.SignatureHeader, error) {
	creator, err := s.Serialize()
	if err != nil {
		return nil, err
	}
	nonce, err := crypto.GetRandomNonce()
	if err != nil {
		return nil, err
	}

	return &common.SignatureHeader{
		Creator: creator,
		Nonce:   nonce,
	}, nil
}

func GetTLSCACerts(files []string) ([][]byte, error) {
	var certs [][]byte
	for _, f := range files {
		in, err := ioutil.ReadFile(f)
		if err != nil {
			return nil, err
		}

		certs = append(certs, in)
	}
	return certs, nil
}

func digest(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}

func toPEM(in []byte) ([]byte, error) {
	d := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(d, in)
	if err != nil {
		return nil, err
	}
	return d[:n], nil
}

// func GetPrivateKey(providerName string, in []byte) (*ecdsa.PrivateKey, error) {
func GetPrivateKey(providerName string, in []byte) (interface{}, error) {
	k, err := utils.PEMtoPrivateKey(in, []byte{})
	if err != nil {
		return nil, err
	}

	return k, nil
	// key, ok := k.(*ecdsa.PrivateKey)
	// if !ok {
	// 	return nil, errors.Errorf("expecting ecdsa key")
	// }

	// return key, nil
}

func GetCertificate(f string) (*x509.Certificate, []byte, error) {
	in, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(in)
	c, err := x509.ParseCertificate(block.Bytes)
	return c, in, err
}
