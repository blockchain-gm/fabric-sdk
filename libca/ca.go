package libca

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fabric-sdk/ca"
	"fabric-sdk/fabric-ca/api"
	"fmt"
	"path"
)

type CaClient struct {
	Cli      *ca.CAClientImpl
	CaConfig *api.CaConfig
}

func NewCaClient(caname string, config *api.FabConfig) (*CaClient, error) {
	var (
		caConfig api.CaConfig
		ok       bool
	)

	if caConfig, ok = config.Ca[caname]; ok {
		ca, err := ca.NewCAClient(caConfig.OrgName,
			caConfig.OrgMSPID,
			caConfig.CaName,
			path.Join(caConfig.KeyStorePath, "signcerts"),
			&ca.EnrollCredentials{EnrollID: caConfig.EnrollID, EnrollSecret: caConfig.EnrollSecret},
			config)
		if err != nil {
			return nil, err
		}
		return &CaClient{Cli: ca, CaConfig: &caConfig}, nil
	}
	return nil, errors.New("ca config not exist")
}

func (ca *CaClient) GetPubKey(ID string) (string, []byte, error) {
	if ca != nil && ca.Cli != nil {
		user, err := ca.Cli.GetSigningIdentity(ID)
		certBytes := user.EnrollmentCertificate()
		if err != nil || certBytes == nil {
			return "", nil, err
		}

		decoded, _ := pem.Decode(certBytes)
		if decoded == nil {
			return "", nil, errors.New("Failed cert decoding")
		}

		x509Cert, err := x509.ParseCertificate(decoded.Bytes)
		if err != nil {
			return "", nil, fmt.Errorf("failed to parse certificate: %s", err)
		}
		if x509Cert.PublicKeyAlgorithm == x509.ECDSA {
			ecdsaPublicKey := x509Cert.PublicKey.(*ecdsa.PublicKey)
			x509EncodedPub, _ := x509.MarshalPKIXPublicKey(ecdsaPublicKey)
			pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
			return x509Cert.PublicKeyAlgorithm.String(), pemEncodedPub, nil
		} else {
			return "", nil, fmt.Errorf("%s", "unknow algorithm parse error")
		}
	}
	return "", nil, fmt.Errorf("%s", "invalid parameter")
}

func (ca *CaClient) GetPriKey(id string) ([]byte, string, error) {
	if ca != nil && ca.Cli != nil {
		prikey, ski, err := ca.Cli.GetUserPriKey(id)
		if err != nil {
			return nil, ski, err
		}
		return prikey, ski, nil
	}
	return nil, "", fmt.Errorf("%s", "invalid parameter")
}

func (ca *CaClient) GetUserCertificate(id string) (*x509.Certificate, []byte, error) {
	return ca.Cli.GetUserCertificate(id)
}

func (ca *CaClient) GetUserKeys(id string) ([]byte, *x509.Certificate, []byte, error) {
	priKey, certBytes, err := ca.Cli.GetUserKeys(id)
	if err != nil {
		return nil, nil, nil, err
	}

	if certBytes != nil {
		decoded, _ := pem.Decode(certBytes)
		if decoded == nil {
			return nil, nil, nil, errors.New("Failed cert decoding")
		}

		cert, err := x509.ParseCertificate(decoded.Bytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse certificate: %s", err)
		}

		return priKey, cert, certBytes, nil
	}

	return nil, nil, nil, fmt.Errorf("%s", "user certificate null")
}

func (ca *CaClient) Sign(id string, msg []byte) (string, error) {
	signature, err := ca.Cli.Sign(id, msg, "SHA256")
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (ca *CaClient) Verify(id string, msg []byte, signature string) error {
	//解码
	signBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	return ca.Cli.Verify(id, msg, signBytes, "SHA256")
}

func (ca *CaClient) Register(request *api.RegistrationRequest) (string, error) {
	var a []api.Attribute
	for i := range request.Attributes {
		a = append(a, api.Attribute{Name: request.Attributes[i].Name, Value: request.Attributes[i].Value, ECert: request.Attributes[i].ECert})
	}

	r := api.RegistrationRequest{
		Name:           request.Name,
		Type:           request.Type,
		MaxEnrollments: request.MaxEnrollments,
		Affiliation:    request.Affiliation,
		Attributes:     a,
		CAName:         request.CAName,
		Secret:         request.Secret,
	}
	return ca.Cli.Register(&r)
}

func (ca *CaClient) Enroll(request *api.EnrollmentRequest) error {
	return ca.Cli.Enroll(request)
}

func (ca *CaClient) GetIdentity(id, caname string) (*api.IdentityResponse, error) {
	return ca.Cli.GetIdentity(id, caname)
}

func (ca *CaClient) GetCAInfo() error {
	caInfo, err := ca.Cli.GetCAInfo()
	if err != nil {
		return err
	}
	fmt.Println("caInfo:", caInfo.CAName, caInfo.Version)

	return nil
}
