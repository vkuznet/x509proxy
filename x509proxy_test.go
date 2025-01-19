package x509proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

// Mock certificate and key
const certPEM = `-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsda823dsfdasds... (truncated)
-----END CERTIFICATE-----`

const keyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsdf324dfdsf4234234234dsf... (truncated)
-----END RSA PRIVATE KEY-----`

func TestAppendByte(t *testing.T) {
	data1 := []byte("hello")
	data2 := []byte(" world")
	result := appendByte(data1, data2)
	expected := "hello world"

	if string(result) != expected {
		t.Errorf("Expected %s, got %s", expected, string(result))
	}
}

func TestGetData(t *testing.T) {
	block := []byte(certPEM + "\n" + keyPEM)
	extractedCert := getData("CERTIFICATE", block)
	extractedKey := getData("RSA PRIVATE KEY", block)

	if len(extractedCert) == 0 {
		t.Error("Failed to extract certificate data")
	}
	if len(extractedKey) == 0 {
		t.Error("Failed to extract key data")
	}
}

func TestIsValid(t *testing.T) {
	now := time.Now()
	validCert := &x509.Certificate{
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(1 * time.Hour),
	}
	expiredCert := &x509.Certificate{
		NotBefore: now.Add(-2 * time.Hour),
		NotAfter:  now.Add(-1 * time.Hour),
	}

	if !isValid(validCert) {
		t.Error("Valid certificate was marked invalid")
	}
	if isValid(expiredCert) {
		t.Error("Expired certificate was marked valid")
	}
}

// Generate a self-signed certificate for testing
func generateTestCert() ([]byte, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	return certPEM, keyPEM, nil
}

func TestX509KeyPair(t *testing.T) {
	certPEM, keyPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	cert, err := x509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to parse key pair: %v", err)
	}
	if cert.PrivateKey == nil {
		t.Error("Private key was not properly parsed")
	}
	if cert.Leaf == nil {
		t.Error("Certificate leaf was not set")
	}
}

func TestLoadX509Proxy(t *testing.T) {
	certPEM, keyPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tmpfile, err := os.CreateTemp("", "proxy.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(certPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := tmpfile.Write(keyPEM); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	cert, err := LoadX509Proxy(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load proxy certificate: %v", err)
	}
	if cert.PrivateKey == nil {
		t.Error("Failed to load private key")
	}
}

// Test ParseCertificate function
func TestParseCertificate(t *testing.T) {
	certPEM, keyPEM, _ := generateTestCert()
	data := append(certPEM, keyPEM...)

	cert, err := ParseCertificate(data)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != "Test Cert" {
		t.Errorf("Expected subject CommonName to be 'Test Cert', got '%s'", cert.Subject.CommonName)
	}
}

// Test GetTlsCert function
func TestGetTlsCert(t *testing.T) {
	certPEM, keyPEM, _ := generateTestCert()
	data := append(certPEM, keyPEM...)

	tlsCert, err := GetTlsCert(data)
	if err != nil {
		t.Fatalf("Failed to parse TLS certificate: %v", err)
	}

	if tlsCert.PrivateKey == nil {
		t.Error("Private key should not be nil")
	}
}

// Test tlsToX509 function
func TestTlsToX509(t *testing.T) {
	certPEM, keyPEM, _ := generateTestCert()
	tlsCert, _ := x509KeyPair(certPEM, keyPEM)

	x509Certs, err := tlsToX509(tlsCert)
	if err != nil {
		t.Fatalf("Failed to convert TLS certificate to X509: %v", err)
	}

	if len(x509Certs) == 0 {
		t.Error("Expected at least one X509 certificate")
	}
}
