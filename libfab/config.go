package libfab

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"fabric-sdk/libca"

	// "github.com/gogo/protobuf/proto"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/msp"
)

type FabConfig struct {
	PeerAddr    string `json:"peer_addr"`
	OrdererAddr string `json:"orderer_addr"`
	Channel     string `json:"channel"`
	Chaincode   string `json:"chaincode"`
	// Args          []string `json:"args"`
	MSPID string `json:"mspid"`
	// PrivateKey    string   `json:"private_key"`
	// SignCert      string   `json:"sign_cert"`
	TLSCACerts []string `json:"tls_ca_certs"`
	// NumOfConn     int      `json:"num_of_conn"`
	// ClientPerConn int      `json:"client_per_conn"`
}

var (
	PeerAddr    string   = "peer0.org1.example.com:7051"
	OrdererAddr string   = "orderer.example.com:7050"
	Channel     string   = "mychannel"
	ChainCode   string   = "standard"
	Mspid       string   = "Org1MSP"
	TLSCaCerts  []string = []string{"/home/liuhy/iview/fabTx/crypto-config/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem", "/home/liuhy/iview/fabTx/crypto-config/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem"}
)

func CheckFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func LoadConfig(parentPath string) (*FabConfig, error) {
	path := filepath.Join(parentPath, "configs/fabconf.json")
	fpath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	config := new(FabConfig)
	if CheckFileIsExist(fpath) { //文件存在
		raw, err := ioutil.ReadFile(fpath)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(raw, config)
		if err != nil {
			return nil, err
		}
	} else {
		config.PeerAddr = PeerAddr
		config.OrdererAddr = OrdererAddr
		config.Channel = Channel
		config.Chaincode = ChainCode
		config.MSPID = Mspid
		config.TLSCACerts = TLSCaCerts

		data, err := json.MarshalIndent(config, "", "   ")
		if err != nil {
			return nil, err
		}

		err = ioutil.WriteFile(fpath, data, 0666)
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}

type OrgEnvOption struct {
	MSPID      string
	TLSCACerts [][]byte
}

func (c *FabConfig) GetEnvCache() (*OrgEnvOption, error) {
	certs, err := GetTLSCACerts(c.TLSCACerts)
	if err != nil {
		return nil, err
	}

	return &OrgEnvOption{
		MSPID:      c.MSPID,
		TLSCACerts: certs,
	}, nil

}

func (o *OrgEnvOption) LoadCrypto(uID string, caClient *libca.CaClient) (*Crypto, error) {
	// conf := CryptoConfig{
	// 	MSPID: o.MSPID,
	// 	// PrivKey:    c.PrivateKey,
	// 	// SignCert:   c.SignCert,
	// 	TLSCACerts: o.TLSCACerts,
	// }

	privateKey, _, err := caClient.GetPriKey(uID)
	priv, err := GetPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	cert, certBytes, err := caClient.GetUserCertificate(uID)
	if err != nil {
		return nil, err
	}

	// cert, certBytes, err := GetCertificate(conf.SignCert)
	// if err != nil {
	// 	panic(err)
	// }

	id := &msp.SerializedIdentity{
		Mspid:   o.MSPID,
		IdBytes: certBytes,
	}
	name, err := proto.Marshal(id)
	if err != nil {
		panic(err)
	}

	// certs, err := GetTLSCACerts(conf.TLSCACerts)
	// if err != nil {
	// 	panic(err)
	// }

	return &Crypto{
		Creator:    name,
		PrivKey:    priv,
		SignCert:   cert,
		TLSCACerts: o.TLSCACerts,
	}, nil
}

// func (c FabConfig) LoadCrypto(uID string, caClient *libca.CaClient) (*Crypto, error) {
// 	crypto := &Crypto{
// 		Name:     uID,
// 		CaClient: caClient,
// 		MSPID:    c.MSPID,
// 	}

// 	_, certBytes, err := crypto.CaClient.GetUserCertificate(uID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// priv, err := GetPrivateKey(conf.PrivKey)
// 	// if err != nil {
// 	// 	panic(err)
// 	// }

// 	// cert, certBytes, err := GetCertificate(conf.SignCert)
// 	// if err != nil {
// 	// 	panic(err)
// 	// }

// 	id := &msp.SerializedIdentity{
// 		Mspid:   crypto.MSPID,
// 		IdBytes: certBytes,
// 	}

// 	identity, err := proto.Marshal(id)
// 	if err != nil {
// 		return nil, err
// 	}

// 	certs, err := GetTLSCACerts(c.TLSCACerts)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// return &Crypto{
// 	// 	Creator:    name,
// 	// 	PrivKey:    priv,
// 	// 	SignCert:   cert,
// 	// 	TLSCACerts: certs,
// 	// }
// 	crypto.Creator = identity
// 	crypto.TLSCACerts = certs
// 	return crypto, nil
// }
