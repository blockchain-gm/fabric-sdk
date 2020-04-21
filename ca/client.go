package ca

import (
	"fabric-sdk/bccsp"
	bccspFactory "fabric-sdk/bccsp/factory"
	"fabric-sdk/fabric-ca/api"
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
	// config := &bccspFactory.FactoryOpts{
	// 	ProviderName: "GM",
	// 	SwOpts: &bccspFactory.SwOpts{
	// 		HashFamily: "GMSM3",
	// 		SecLevel:   256,
	// 		Ephemeral:  false,
	// 		FileKeystore: &bccspFactory.FileKeystoreOpts{
	// 			KeyStorePath: "./keys",
	// 		},
	// 	},
	// }

	config := &bccspFactory.FactoryOpts{
		ProviderName: "SW",
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

func GetCAConfig(fconfig *api.CaConfig) (*CAConfig, error) {
	var (
		err error
	)

	caConfig := &CAConfig{
		ID:             fconfig.CaID, //"ca.org1.example.com",
		URL:            fconfig.URL,  // "http://ca.org1.example.com:7054",
		GRPCOptions:    make(map[string]interface{}),
		Registrar:      EnrollCredentials{EnrollID: fconfig.EnrollID, EnrollSecret: fconfig.EnrollSecret}, // EnrollCredentials{EnrollID: "root", EnrollSecret: "adminpw"},
		CAName:         fconfig.CaName,                                                                    // "ca-org1",
		caKeyStorePath: fconfig.KeyStorePath,                                                              //"./keys",
	}

	caConfig.GRPCOptions["ssl-target-name-override"] = fconfig.SSLOverride //"127.0.0.1"

	if IsTLSEnabled(caConfig.URL) {
		// caConfig.TLSCAServerCerts, err = getServerCerts("./crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem")
		caConfig.TLSCAServerCerts, err = getServerCerts(fconfig.TLS.ServerCertPath)
		if err != nil {
			return nil, err
		}

		// caConfig.TLSCAClientKey, err = LoadBytes("crypto-config/peerOrganizations/org1.example.com/ca/00a81ff19d1fc744d5dc8c20f5bf61488ce6a9714f080642449c8327695e5789_sk")
		caConfig.TLSCAClientKey, err = LoadBytes(fconfig.TLS.ClientKeyPath)
		if err != nil {
			return nil, err
		}

		// caConfig.TLSCAClientCert, err = LoadBytes("crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem")
		caConfig.TLSCAClientCert, err = LoadBytes(fconfig.TLS.ClientCertPath)
		if err != nil {
			return nil, err
		}
	}
	return caConfig, nil
}

func GetMspClient(workDir string, fconfig *api.CaConfig) (*MspClient, error) {
	var (
		err      error
		caClient = new(MspClient)
	)

	caClient.CAConfig, err = GetCAConfig(fconfig)
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
