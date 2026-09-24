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
	certOnce       sync.Once
	cachedUTLS     *utls.Certificate
	cachedX509     *tls.Certificate
	cachedCertPEM  []byte
	cachedKeyPEM   []byte
	certErr        error
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

// SetCertPersistDir prefers PEMs under dir when present. The probe always also
// loads/saves a machine-wide durable pair (see DurableCertDir) so switching
// --capture-dir does not mint a new Root CA and break Firefox trust.
func SetCertPersistDir(dir string) {
	certPersistDir = dir
}

// DurableCertDir is the stable location for the probe Root CA across runs.
// Override with COHERENCELAB_CERT_DIR.
func DurableCertDir() string {
	if d := os.Getenv("COHERENCELAB_CERT_DIR"); d != "" {
		return d
	}
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "coherencelab")
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
	// Prefer capture-dir PEMs, then machine-wide durable PEMs, else mint once.
	candidates := []string{}
	if certPersistDir != "" {
		candidates = append(candidates, certPersistDir)
	}
	candidates = append(candidates, DurableCertDir())
	for _, dir := range candidates {
		if err := loadCertPEMs(dir); err == nil {
			// Mirror into the other locations so serve --capture-dir always
			// exposes the same Root CA the browser was told to trust.
			_ = mirrorCachedPEMs(candidates)
			return
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		certErr = err
		return
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		certErr = err
		return
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "CoherenceLab Probe",
			Organization: []string{"CoherenceLab"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
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
	if err := mirrorCachedPEMs(candidates); err != nil {
		certErr = fmt.Errorf("persist probe cert: %w", err)
	}
}

func mirrorCachedPEMs(dirs []string) error {
	seen := map[string]bool{}
	var last error
	for _, dir := range dirs {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		if _, _, err := writeCertPEMsTo(dir); err != nil {
			last = err
		}
	}
	return last
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
