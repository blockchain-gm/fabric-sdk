package api

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
	TLS          *CaTLS
}

type FabConfig struct {
	SecType string
	SW      BCCSP
	GM      BCCSP
	Ca      map[string]CaConfig
}
