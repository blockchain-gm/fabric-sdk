package ca

import (
	"fabric-sdk/bccsp"
	bccspFactory "fabric-sdk/bccsp/factory"
	// "github.com/hyperledger/fabric-sdk-go/pkg/util/pathvar"
)

type MspClient struct {
	// Sdk             *fabsdk.FabricSDK
	// MspClient *Client
	CAConfig *CAConfig
	// CryptoConfig    core.CryptoSuiteConfig
	MyBCCSP bccsp.BCCSP
	MSPID   string
	// CryptoStorePath string
}

func initCryptoSuite() (bccsp.BCCSP, error) {
	config := &bccspFactory.FactoryOpts{
		ProviderName: "GM",
		SwOpts: &bccspFactory.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,
			Ephemeral:  false,
			FileKeystore: &bccspFactory.FileKeystoreOpts{
				KeyStorePath: "./keys",
			},
		},
	}
	err := bccspFactory.InitFactories(config)
	if err != nil {
		return nil, err
	}

	return bccspFactory.GetDefault(), nil
}

// type CAConfig struct {
// 	ID               string
// 	URL              string
// 	GRPCOptions      map[string]interface{}
// 	Registrar        EnrollCredentials
// 	CAName           string
// 	TLSCAServerCerts [][]byte
// 	TLSCAClientCert  []byte
// 	TLSCAClientKey   []byte
// }

func GetCAConfig() (*CAConfig, error) {
	var (
		err error
	)

	caConfig := &CAConfig{
		ID:          "ca.org1.example.com",
		URL:         "http://ca.org1.example.com:7054",
		GRPCOptions: make(map[string]interface{}),
		Registrar:   EnrollCredentials{EnrollID: "admin", EnrollSecret: "adminpw"},
		CAName:      "ca-org1",
	}

	caConfig.GRPCOptions["ssl-target-name-override"] = "127.0.0.1"
	caConfig.TLSCAServerCerts, err = getServerCerts("./crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem")
	if err != nil {
		return nil, err
	}

	caConfig.TLSCAClientKey, err = LoadBytes("crypto-config/peerOrganizations/org1.example.com/ca/80a1b0bdb205aad91b915ad0c2bfeded0b440ea7d32b191155b9b5702b0229e0_sk")
	if err != nil {
		return nil, err
	}

	caConfig.TLSCAClientCert, err = LoadBytes("crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem")
	if err != nil {
		return nil, err
	}

	return caConfig, nil

}

func GetMspClient(workDir string) (*MspClient, error) {
	var (
		err      error
		caClient = new(MspClient)
	)

	caClient.CAConfig, err = GetCAConfig()
	if err != nil {
		return nil, err
	}

	caClient.MyBCCSP, err = initCryptoSuite()
	if err != nil {
		return nil, err
	}

	caClient.MSPID = "Org1MSP"
	return caClient, nil
}
