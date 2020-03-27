package ca

import (
	"io/ioutil"
	"strings"

	"github.com/pkg/errors"
)

func getServerCerts(path string) ([][]byte, error) {
	var serverCerts [][]byte

	//check for files if pems not found
	certFiles := strings.Split(path, ",")
	serverCerts = make([][]byte, len(certFiles))
	for i, certPath := range certFiles {
		bytes, err := ioutil.ReadFile(Subst(certPath))
		if err != nil {
			return nil, errors.WithMessage(err, "failed to load server certs")
		}
		serverCerts[i] = bytes
	}

	return serverCerts, nil
}

//Pem takes precedence over Path
func LoadBytes(path string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load pem bytes from path %s", path)
	}
	return bytes, nil
}
