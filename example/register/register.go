package main

import (
	"fabric-sdk/ca"
	"fabric-sdk/fabric-ca/api"
	"fmt"
)

func Register(request *api.RegistrationRequest) (string, error) {
	ca, err := ca.NewCAClient("org1", "mspOrg1", "ca-org1", "./keys", &ca.EnrollCredentials{EnrollID: "admin", EnrollSecret: "adminpw"})
	if err != nil {
		return "", err
	}

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
	return ca.Register(&r)
}

func main() {
	pwd, err := Register(&api.RegistrationRequest{Name: "liuhy"})
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(pwd)
}
