package probe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

var (
	certOnce      sync.Once
	cachedUTLS    *utls.Certificate
	cachedX509    *tls.Certificate
	cachedCertPEM []byte
	cachedKeyPEM  []byte
	certErr       error
	certPersistDir string
)

func generateSelfSigned() (*utls.Certificate, error) {
	certOnce.Do(buildCerts)
	return cachedUTLS, certErr
}

func generateSelfSignedX509() (*tls.Certificate, error) {
	certOnce.Do(buildCerts)
	return cachedX509, certErr
}

// SetCertPersistDir makes the probe reuse a durable PEM pair under dir so
// browsers that trust the Root CA keep working across serve restarts (needed
// for Chrome QUIC, which often ignores --ignore-certificate-errors).
func SetCertPersistDir(dir string) {
	certPersistDir = dir
}

// WriteCertPEMs writes the probe certificate and key for browser trust import.
func WriteCertPEMs(dir string) (certPath, keyPath string, err error) {
	certOnce.Do(buildCerts)
	if certErr != nil {
		return "", "", certErr
	}
	return writeCertPEMsTo(dir)
}

func writeCertPEMsTo(dir string) (certPath, keyPath string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	certPath = filepath.Join(dir, "probe-cert.pem")
	keyPath = filepath.Join(dir, "probe-key.pem")
	if err := os.WriteFile(certPath, cachedCertPEM, 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, cachedKeyPEM, 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func buildCerts() {
	if certPersistDir != "" {
		if err := loadCertPEMs(certPersistDir); err == nil {
			return
		}
	}
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
		IsCA:                  true,
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
	if err := cacheFromPEM(certPEM, keyPEM); err != nil {
		certErr = err
		return
	}
	if certPersistDir != "" {
		if _, _, err := writeCertPEMsTo(certPersistDir); err != nil {
			certErr = fmt.Errorf("persist probe cert: %w", err)
		}
	}
}

func loadCertPEMs(dir string) error {
	certPEM, err := os.ReadFile(filepath.Join(dir, "probe-cert.pem"))
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "probe-key.pem"))
	if err != nil {
		return err
	}
	return cacheFromPEM(certPEM, keyPEM)
}

func cacheFromPEM(certPEM, keyPEM []byte) error {
	ucert, err := utls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	xcert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	cachedUTLS = &ucert
	cachedX509 = &xcert
	cachedCertPEM = certPEM
	cachedKeyPEM = keyPEM
	return nil
}
