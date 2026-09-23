package probe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

var (
	certOnce   sync.Once
	cachedUTLS *utls.Certificate
	cachedX509 *tls.Certificate
	certErr    error
)

func generateSelfSigned() (*utls.Certificate, error) {
	certOnce.Do(buildCerts)
	return cachedUTLS, certErr
}

func generateSelfSignedX509() (*tls.Certificate, error) {
	certOnce.Do(buildCerts)
	return cachedX509, certErr
}

func buildCerts() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		certErr = err
		return
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "CoherenceLab Probe",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "example.com"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		certErr = err
		return
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		certErr = err
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	ucert, err := utls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		certErr = err
		return
	}
	xcert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		certErr = err
		return
	}
	cachedUTLS = &ucert
	cachedX509 = &xcert
}
