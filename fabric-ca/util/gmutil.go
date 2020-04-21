package util

import (
	"crypto/x509"
	"encoding/pem"
	log "fabric-sdk/fabric-ca/sdkpatch/logbridge"

	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
)

func GetX509CertificateFromRaw(providerName string, cert []byte) (interface{}, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.Errorf("Unable to decode cert bytes [%v]", cert)
	}

	if providerName == "GM" {
		sm2x509Cert, err := sm2.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "Error parsing GM certificate")
		}
		return sm2x509Cert, nil
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing X509 certificate")
	}
	return x509Cert, nil
}

func GetX509CertificateFromGMPEM(providerName string, cert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("Failed to PEM decode certificate")
	}
	var x509Cert *x509.Certificate
	var err error
	if providerName == "GM" {
		log.Debugf("IsGMConfig = true")
		sm2x509Cert, err := sm2.ParseCertificate(block.Bytes)
		if err == nil {
			x509Cert = ParseSm2Certificate2X509(sm2x509Cert)
			log.Debugf("after parse,x509Cert=%T,x509Cert.PublicKey=%T", x509Cert, x509Cert.PublicKey)
		}
	} else {
		x509Cert, err = x509.ParseCertificate(block.Bytes)
	}
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing certificate")
	}
	return x509Cert, nil
}

//sm2 证书转换 x509 证书
func ParseSm2Certificate2X509(sm2Cert *sm2.Certificate) *x509.Certificate {
	x509cert := &x509.Certificate{
		Raw:                     sm2Cert.Raw,
		RawTBSCertificate:       sm2Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo: sm2Cert.RawSubjectPublicKeyInfo,
		RawSubject:              sm2Cert.RawSubject,
		RawIssuer:               sm2Cert.RawIssuer,

		Signature:          sm2Cert.Signature,
		SignatureAlgorithm: x509.SignatureAlgorithm(sm2Cert.SignatureAlgorithm),

		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(sm2Cert.PublicKeyAlgorithm),
		PublicKey:          sm2Cert.PublicKey,

		Version:      sm2Cert.Version,
		SerialNumber: sm2Cert.SerialNumber,
		Issuer:       sm2Cert.Issuer,
		Subject:      sm2Cert.Subject,
		NotBefore:    sm2Cert.NotBefore,
		NotAfter:     sm2Cert.NotAfter,
		KeyUsage:     x509.KeyUsage(sm2Cert.KeyUsage),

		Extensions: sm2Cert.Extensions,

		ExtraExtensions: sm2Cert.ExtraExtensions,

		UnhandledCriticalExtensions: sm2Cert.UnhandledCriticalExtensions,

		//ExtKeyUsage:	[]x509.ExtKeyUsage(sm2Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage: sm2Cert.UnknownExtKeyUsage,

		BasicConstraintsValid: sm2Cert.BasicConstraintsValid,
		IsCA:                  sm2Cert.IsCA,
		MaxPathLen:            sm2Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: sm2Cert.MaxPathLenZero,

		SubjectKeyId:   sm2Cert.SubjectKeyId,
		AuthorityKeyId: sm2Cert.AuthorityKeyId,

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            sm2Cert.OCSPServer,
		IssuingCertificateURL: sm2Cert.IssuingCertificateURL,

		// Subject Alternate Name values
		DNSNames:       sm2Cert.DNSNames,
		EmailAddresses: sm2Cert.EmailAddresses,
		IPAddresses:    sm2Cert.IPAddresses,

		// Name constraints
		PermittedDNSDomainsCritical: sm2Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         sm2Cert.PermittedDNSDomains,

		// CRL Distribution Points
		CRLDistributionPoints: sm2Cert.CRLDistributionPoints,

		PolicyIdentifiers: sm2Cert.PolicyIdentifiers,
	}
	for _, val := range sm2Cert.ExtKeyUsage {
		x509cert.ExtKeyUsage = append(x509cert.ExtKeyUsage, x509.ExtKeyUsage(val))
	}

	return x509cert
}
