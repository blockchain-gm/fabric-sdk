package main

import (
	"fabric-sdk/ca"
	"fabric-sdk/fabric-ca/api"
	"fmt"
	"math/rand"
	"time"
)

var r *rand.Rand

func init() {
	r = rand.New(rand.NewSource(time.Now().Unix()))
}

func RandString(len int) string {
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		b := r.Intn(26) + 65
		bytes[i] = byte(b)
	}
	return string(bytes)
}

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
	fmt.Printf("%+v", *identInfo)
}
