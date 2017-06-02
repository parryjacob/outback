package outback

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

func parseKeyAndCertificate(keyFile string, certFile string) (crypto.PrivateKey, *x509.Certificate, error) {
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyBytes)
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}
