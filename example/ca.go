package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fabric-sdk/ca"
	"fabric-sdk/fabric-ca/api"
	"fmt"
	"math/rand"
	"time"
)

var r *rand.Rand

func init() {
	r = rand.New(rand.NewSource(time.Now().UnixNano()))
}

func RandString(len int) string {
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		b := r.Intn(26) + 65
		bytes[i] = byte(b)
	}
	return string(bytes)
}

// const (
// 	// NonceSize is the default NonceSize
// 	NonceSize = 24
// )

// // GetRandomBytes returns len random looking bytes
// func GetRandomBytes(len int) (string, error) {
// 	key := make([]byte, len)

// 	// TODO: rand could fill less bytes then len
// 	_, err := rand.Read(key)
// 	if err != nil {
// 		return "", err
// 	}

// 	return base64.StdEncoding.EncodeToString(key), nil
// }

type CaClient struct {
	Cli *ca.CAClientImpl
}

func NewCaClient() (*CaClient, error) {
	ca, err := ca.NewCAClient("org1", "mspOrg1", "ca-org1", "./keys/signcerts", &ca.EnrollCredentials{EnrollID: "root", EnrollSecret: "adminpw"})
	if err != nil {
		return nil, err
	}
	return &CaClient{Cli: ca}, nil
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

func (ca *CaClient) GetPriKey(ID string) ([]byte, string, error) {
	if ca != nil && ca.Cli != nil {
		prikey, ski, err := ca.Cli.GetUserPriKey(ID)
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

func main() {
	ca, err := NewCaClient()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	ca.GetCAInfo()

	name := RandString(10)
	pwd, err := ca.Register(&api.RegistrationRequest{Name: name})
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(name, pwd)

	err = ca.Enroll(&api.EnrollmentRequest{Name: name, Secret: pwd})
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	identInfo, err := ca.GetIdentity(name, "ca-org1")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("%+v\n", *identInfo)

	alg, pubKey, err := ca.GetPubKey(name)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("GetPubKey:", alg)
	fmt.Println("GetPubKey:", string(pubKey))

	priKey, ski, err := ca.GetPriKey(name)
	if err != nil {
		fmt.Println("GetPriKey:", err.Error())
		return
	}
	fmt.Println("GetPriKey:", string(priKey))
	fmt.Println("pri key ski:", ski)

	_, cert, err := ca.GetUserCertificate(name)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("cert:", string(cert))

	signature, err := ca.Sign(name, []byte("hello world"))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("signature: %s", signature)

	err = ca.Verify(name, []byte("hello world"), signature)
	if err != nil {
		fmt.Printf("Verify: %s", err.Error())
	}
	fmt.Println("signature ok")
}
