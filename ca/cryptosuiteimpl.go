package ca

import (
	"fabric-sdk/bccsp"
	bccspSw "fabric-sdk/bccsp/factory"
	"fabric-sdk/bccsp/sw"

	"github.com/pkg/errors"
)

func GetSuiteByConfig() (bccsp.BCCSP, error) {
	opts := getOptsByConfig()
	bccsp, err := getBCCSPFromOpts(opts)
	if err != nil {
		return nil, err
	}
	return bccsp, nil
}

func GetSuiteWithDefaultEphemeral() (bccsp.BCCSP, error) {
	opts := getEphemeralOpts()

	bccsp, err := getBCCSPFromOpts(opts)
	if err != nil {
		return nil, err
	}
	return bccsp, nil
}

func getBCCSPFromOpts(config *bccspSw.SwOpts) (bccsp.BCCSP, error) {
	f := &bccspSw.SWFactory{}

	conf := &bccspSw.FactoryOpts{
		ProviderName: "SW",
		SwOpts:       config,
	}

	csp, err := f.Get(conf)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}

func GetSuite(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	bccsp, err := sw.NewWithParams(securityLevel, hashFamily, keyStore)
	if err != nil {
		return nil, err
	}
	return bccsp, nil
}

//GetOptsByConfig Returns Factory opts for given SDK config
func getOptsByConfig() *bccspSw.SwOpts {
	opts := &bccspSw.SwOpts{
		HashFamily: "SHA2",
		SecLevel:   256,
		FileKeystore: &bccspSw.FileKeystoreOpts{
			KeyStorePath: "./keys",
		},
	}
	// logger.Debug("Initialized SW cryptosuite")

	return opts
}

func getEphemeralOpts() *bccspSw.SwOpts {
	opts := &bccspSw.SwOpts{
		HashFamily: "SHA2",
		SecLevel:   256,
		Ephemeral:  false,
	}
	// logger.Debug("Initialized ephemeral SW cryptosuite with default opts")

	return opts
}
