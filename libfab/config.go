package libfab

import (
	"encoding/json"
	"fabric-sdk/libca"
	"io/ioutil"
	"os"
	"path/filepath"

	// "github.com/gogo/protobuf/proto"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/msp"
)

type FabConfig struct {
	PeerAddr    string   `json:"peer_addr"`
	OrdererAddr string   `json:"orderer_addr"`
	Channel     string   `json:"channel"`
	Chaincode   string   `json:"chaincode"`
	MSPID       string   `json:"mspid"`
	TLSCACerts  []string `json:"tls_ca_certs"`
}

var (
	PeerAddr    string   = "peer0.org1.example.com:7051"
	OrdererAddr string   = "orderer.example.com:7050"
	Channel     string   = "mychannel"
	ChainCode   string   = "standard"
	Mspid       string   = "Org1MSP"
	TLSCaCerts  []string = []string{"./crypto-config/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem", "./crypto-config/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem"}
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
	privateKey, cert, certBytes, err := caClient.GetUserKeys(uID)
	if err != nil {
		return nil, err
	}
	priv, err := GetPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	id := &msp.SerializedIdentity{
		Mspid:   o.MSPID,
		IdBytes: certBytes,
	}
	name, err := proto.Marshal(id)
	if err != nil {
		panic(err)
	}

	return &Crypto{
		Creator:    name,
		PrivKey:    priv,
		SignCert:   cert,
		TLSCACerts: o.TLSCACerts,
	}, nil
}
