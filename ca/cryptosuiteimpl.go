package ca

import (
	"fabric-sdk/bccsp"
	bccspSw "fabric-sdk/bccsp/factory"
	"fabric-sdk/bccsp/sw"

	"github.com/pkg/errors"
)

func GetSuiteByConfig(secType string) (bccsp.BCCSP, error) {
	var (
		opts *bccspSw.SwOpts
	)

	//select SW or GM
	opts = getOptsByConfig(secType)

	bccsp, err := getBCCSPFromOpts(secType, opts)
	if err != nil {
		return nil, err
	}
	return bccsp, nil
}

func GetSuiteWithDefaultEphemeral(secType string) (bccsp.BCCSP, error) {
	var (
		opts *bccspSw.SwOpts
	)

	opts = getEphemeralOpts()

	bccsp, err := getBCCSPFromOpts(secType, opts)
	if err != nil {
		return nil, err
	}
	return bccsp, nil
}

func getBCCSPFromOpts(secType string, config *bccspSw.SwOpts) (bccsp.BCCSP, error) {
	if secType == "SW" {
		f := &bccspSw.SWFactory{}
		conf := &bccspSw.FactoryOpts{
			ProviderName: "SW",
			// ProviderName: secType,
			SwOpts: config,
		}

		csp, err := f.Get(conf)
		if err != nil {
			return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
		}
		return csp, nil
	}

	f := &bccspSw.GMFactory{}
	conf := &bccspSw.FactoryOpts{
		ProviderName: "GM",
		// ProviderName: secType,
		SwOpts: config,
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
func getOptsByConfig(secType string) *bccspSw.SwOpts {
	if secType == "SW" {
		opts := &bccspSw.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,
			FileKeystore: &bccspSw.FileKeystoreOpts{
				KeyStorePath: "./keys/keystore",
			},
		}
		// logger.Debug("Initialized SW cryptosuite")

		return opts
	}

	opts := &bccspSw.SwOpts{
		HashFamily: "GMSM3",
		SecLevel:   256,
		FileKeystore: &bccspSw.FileKeystoreOpts{
			KeyStorePath: "./keys/keystore",
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
