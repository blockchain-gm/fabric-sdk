package main

import (
	"fabric-sdk/fabric-ca/api"
	"fabric-sdk/libca"
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

func main() {
	config, err := libca.LoadDBConfig("./")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(config)

	ca, err := libca.NewCaClient()
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
	fmt.Println("priKey SKI:", ski)

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
