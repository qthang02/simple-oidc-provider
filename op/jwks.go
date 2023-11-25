package op

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"math/big"
	"os"
	"time"
)

var (
	ErrFailedToGenerateKey           = errors.New("failed to generate private key")
	ErrFailedToCreatedCertificate    = errors.New("failed to create certificate")
	ErrFailedToWriteCertificate      = errors.New("failed to open certificate.pem for writing")
	ErrFailedToParseCertificate      = errors.New("failed to parse certificate PEM")
	ErrFailedToDecodeCertificate     = errors.New("failed to decode certificate PEM")
	ErrCannotOpenToWriteCertificate  = errors.New("cannot open to write certificate")
	ErrCannotCloseToWriteCertificate = errors.New("cannot close to write certificate")
)

func (pro *Provider) JwkHandler() (*jose.JSONWebKeySet, error) {
	_, publicKey, err := pro.GenerateJWKs()
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func (pro *Provider) GenerateJWKs() (*rsa.PrivateKey, *jose.JSONWebKeySet, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, ErrFailedToGenerateKey
	}

	// generate certificate PEM
	certPEM, err := generateCertPEM(privateKey, "localhost", "VN", "VNCloud", "HCM", false)

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, ErrFailedToDecodeCertificate
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, ErrFailedToParseCertificate
	}

	x5t := sha1.Sum(cert.Raw)

	// Create a JWK from the RSA private key
	//privateJWK := &jose.JSONWebKey{
	//	Key:                       privateKey,
	//	KeyID:                     "YourKid",
	//	Algorithm:                 "RS256",
	//	Use:                       "sig",
	//	CertificateThumbprintSHA1: x5t[:],
	//	Certificates:              []*x509.Certificate{cert},
	//}

	// Create a JWK from the RSA public key
	publicJWK := jose.JSONWebKey{
		Key:                       privateKey.Public(),
		KeyID:                     "YourKid",
		Algorithm:                 "RS256",
		Use:                       "sig",
		CertificateThumbprintSHA1: x5t[:],
		Certificates:              []*x509.Certificate{cert},
	}

	//privateJWKs := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateJWK}}
	publicJWKs := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK}}

	return privateKey, publicJWKs, nil
}

func generateCertPEM(privateKey *rsa.PrivateKey, commonName, country, organization, province string, isWriteFile bool) ([]byte, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for one year

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Country:      []string{country},
			Organization: []string{organization},
			Province:     []string{province},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, ErrFailedToCreatedCertificate
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if isWriteFile {
		certOut, err := os.Create("certificate.pem")
		if err != nil {
			return nil, ErrCannotOpenToWriteCertificate
		}
		err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		if err != nil {
			return nil, ErrFailedToWriteCertificate
		}
		err = certOut.Close()
		if err != nil {
			return nil, ErrCannotCloseToWriteCertificate
		}
		fmt.Print("written cert.pem\n")
	}

	return certPEM, nil
}
