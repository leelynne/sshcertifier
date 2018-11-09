package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

func getTLSConfig() (*tls.Config, error) {
	cert, err := gencert()
	if err != nil {
		return nil, errors.Wrapf(err, "Could not generate local TLS cert")
	}
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		/*CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},*/
		Certificates: []tls.Certificate{cert},
	}, nil
}

func gencert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, errors.Wrapf(err, "failed to generate private key")
	}

	notBefore := time.Now()
	expire := 900 * 24 * time.Hour
	notAfter := notBefore.Add(expire)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, errors.Wrapf(err, "failed to generate serial number")
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"sshcertifier"},
			OrganizationalUnit: []string{"sshcertifier"},
			CommonName:         "sshcertifier",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, errors.Wrapf(err, "Failed to create certificate")
	}

	var certBuf, keyBuf bytes.Buffer

	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return tls.Certificate{}, errors.Wrapf(err, "failed to write data to cert.pem")
	}
	block, err := pemBlockForKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	if err := pem.Encode(&keyBuf, block); err != nil {
		return tls.Certificate{}, errors.Wrapf(err, "failed to write data to key.pem")
	}

	return tls.X509KeyPair(certBuf.Bytes(), keyBuf.Bytes())
}

func pemBlockForKey(priv *ecdsa.PrivateKey) (*pem.Block, error) {
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to marshal ECDSA private key: %v", priv)
	}
	return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
}
