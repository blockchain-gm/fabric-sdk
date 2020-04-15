package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	SEC_TYPE = "SW"

	SW_PROVIDER = "SW"
	SW_HASHALGO = "SHA2"
	SW_LEVEL    = 256

	GM_PROVIDER = "GM"
	GM_HASHALGO = "gmsm3"
	GM_LEVEL    = 256

	ORG_NAME      = "org1"
	ORG_MSPID     = "mspOrg1"
	CA_NAME       = "ca-org1"
	KEY_STOREPATH = "keys"
	ENROLL_ID     = "root"
	ENROLL_SECRET = "adminpwd"
	CA_ID         = "ca.org1.example.com"
	URL           = "http://ca.org1.example.com:7054"
	SSL_OVERRIDE  = "127.0.0.1"

	TLS_CA_SERVER_CERT = "./configs/ssl/ca.org1.example.com-cert.pem"
	TLS_CA_CLIENT_KEY  = "./configs/ssl/00a81ff19d1fc744d5dc8c20f5bf61488ce6a9714f080642449c8327695e5789_sk"
	TLS_CA_CLIENT_CERT = "./configs/ssl/ca.org1.example.com-cert.pem"
)

type BCCSP struct {
	Provider string //defalut SW
	HashAlgo string //default SHA2
	Level    int    //256
}

type CaTLS struct {
	ServerCertPath string
	ClientKeyPath  string
	ClientCertPath string
}

type CaConfig struct {
	OrgName      string
	OrgMSPID     string
	CaName       string
	KeyStorePath string
	EnrollID     string
	EnrollSecret string
	CaID         string
	URL          string
	SSLOverride  string
	Tls          *CaTLS
}

type FabConfig struct {
	SecType string
	SW      BCCSP
	GM      BCCSP
	Ca      map[string]CaConfig
}

func CheckFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func LoadDBConfig(parentPath string) (*FabConfig, error) {
	path := filepath.Join(parentPath, "configs/fabconf.json")
	fpath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	config := new(FabConfig)
	if CheckFileIsExist(fpath) { //文件存在
		bs, err := ioutil.ReadFile(fpath)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(bs, config)
		if err != nil {
			return nil, err
		}
	} else {
		config.SecType = SEC_TYPE
		config.SW = BCCSP{
			Provider: SW_PROVIDER,
			HashAlgo: SW_HASHALGO,
			Level:    SW_LEVEL,
		}
		config.GM = BCCSP{
			Provider: GM_PROVIDER,
			HashAlgo: GM_HASHALGO,
			Level:    GM_LEVEL,
		}

		config.Ca = map[string]CaConfig{
			CA_NAME: CaConfig{
				OrgName:      ORG_NAME,
				OrgMSPID:     ORG_MSPID,
				CaName:       CA_NAME,
				KeyStorePath: KEY_STOREPATH,
				EnrollID:     ENROLL_ID,
				EnrollSecret: ENROLL_SECRET,
				CaID:         CA_ID,
				URL:          URL,
				SSLOverride:  SSL_OVERRIDE,
				Tls: &CaTLS{
					ServerCertPath: TLS_CA_SERVER_CERT,
					ClientKeyPath:  TLS_CA_CLIENT_KEY,
					ClientCertPath: TLS_CA_CLIENT_CERT,
				},
			},
		}

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

// func main() {
// 	config, err := LoadDBConfig("./")
// 	if err != nil {
// 		fmt.Println(err.Error())
// 		return
// 	}
// 	fmt.Println(config)
// }