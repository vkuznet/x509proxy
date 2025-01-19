package x509proxy

// Author     : Valentin Kuznetsov <vkuznet AT gmail dot com>
// Description: x509 proxy certificate parser utilities
// Created    : Wed Mar 20 13:29:48 EDT 2013
// License    : MIT

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"regexp"
	"time"
)

// Helper function to append bytes to existing slice
func appendByte(slice []byte, data []byte) []byte {
	m := len(slice)
	n := m + len(data)
	if n > cap(slice) { // if necessary, reallocate
		// allocate double what's needed, for future growth.
		newSlice := make([]byte, (n+1)*2)
		copy(newSlice, slice)
		slice = newSlice
	}
	slice = slice[0:n]
	copy(slice[m:n], data)
	return slice
}

// Helper function to get specific part of certificate/key file specified by
// mkey, e.g. CERTIFICATE or KEY
func getData(mkey string, block []byte) (keyBlock []byte) {
	newline := []byte("\n")
	out := []byte{}
	start := 0
	keyMatch := 0
	for i := 0; i < len(block); i++ {
		out = block[start:i]
		if string(block[i]) == "\n" {
			test, _ := regexp.MatchString(mkey, string(out))
			if test {
				keyMatch++
			}
			if keyMatch > 0 {
				keyBlock = appendByte(keyBlock, out)
				keyBlock = appendByte(keyBlock, newline)
				if keyMatch == 2 {
					keyMatch = 0
				}
			}
			out = []byte{}
			start = i + 1
		}
	}
	return
}

// helper function to check user certficate validity
func isValid(cert *x509.Certificate) bool {
	notAfter := cert.NotAfter.Unix()
	notBefore := cert.NotBefore.Unix()
	rightNow := time.Now().Unix()
	return notBefore < rightNow && rightNow < notAfter
}

// tlsToX509 converts a tls.Certificate to an x509.Certificate
func tlsToX509(tlsCert tls.Certificate) ([]*x509.Certificate, error) {
	var x509Certs []*x509.Certificate

	for _, certDER := range tlsCert.Certificate {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, err
		}
		x509Certs = append(x509Certs, cert)
	}

	return x509Certs, nil
}

// GetTlsCert parses a single certificate from the given ASN.1 DER data and X509 proxy
func GetTlsCert(der []byte) (*tls.Certificate, error) {
	// read CERTIFICATE blocks
	certPEMBlock := getData("CERTIFICATE", der)

	// read KEY block
	keyPEMBlock := getData("KEY", der)

	tlsCert, err := x509KeyPair(certPEMBlock, keyPEMBlock)
	return &tlsCert, err
}

// ParseCertificate parses a single certificate from the given ASN.1 DER data and X509 proxy
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	// read CERTIFICATE blocks
	certPEMBlock := getData("CERTIFICATE", der)

	// read KEY block
	keyPEMBlock := getData("KEY", der)

	tlsCert, err := x509KeyPair(certPEMBlock, keyPEMBlock)
	x509Certs, err := tlsToX509(tlsCert)
	return x509Certs[0], err
}

// LoadX509Proxy reads and parses a chained proxy file
// which contains PEM encoded data. It returns X509KeyPair.
// It is slightly modified version of tls.LoadX509Proxy function with addition
// of custom parse function (getData) for provided proxy file
func LoadX509Proxy(proxyFile string) (cert tls.Certificate, err error) {
	file, err := os.Open(proxyFile)
	if err != nil {
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return
	}

	// read CERTIFICATE blocks
	certPEMBlock := getData("CERTIFICATE", data)

	// read KEY block
	keyPEMBlock := getData("KEY", data)

	return x509KeyPair(certPEMBlock, keyPEMBlock)
}

// LoadX509KeyPair parses a public/private key pair from a pair of PEM encoded
// data.  It is slightly modified version of tls.X509Proxy where Leaf
// assignment is made to make proxy certificate works.
func LoadX509KeyPair(serverCrt, serverKey string) (cert tls.Certificate, err error) {
	emptyCert := tls.Certificate{}
	// read CERTIFICATE blocks from cert file
	file, err := os.Open(serverCrt)
	if err != nil {
		return emptyCert, err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return emptyCert, err
	}
	certPEMBlock := getData("CERTIFICATE", data)

	// read KEY block from key file
	file, err = os.Open(serverKey)
	if err != nil {
		return emptyCert, err
	}
	defer file.Close()
	data, err = io.ReadAll(file)
	if err != nil {
		return emptyCert, err
	}
	keyPEMBlock := getData("KEY", data)

	return x509KeyPair(certPEMBlock, keyPEMBlock)
}

// Parse a public/private key pair from a pair of PEM encoded
// data.  It is slightly modified version of tls.X509Proxy where Leaf
// assignment is made to make proxy certificate works.
func x509KeyPair(certPEMBlock, keyPEMBlock []byte) (cert tls.Certificate, err error) {
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		// parse certificates
		certs, err2 := x509.ParseCertificates(certDERBlock.Bytes)
		if err2 == nil {
			// assign the Leaf
			if len(certs) > 0 {
				cert.Leaf = certs[0]
			}

			for _, c := range certs {
				if !isValid(c) {
					err = errors.New("Certificate is expired")
					return
				}
			}

		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}

	if len(cert.Certificate) == 0 {
		err = errors.New("crypto/tls: failed to parse certificate PEM data")
		return
	}

	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil {
		err = errors.New("crypto/tls: failed to parse key PEM data")
		return
	}

	// OpenSSL 0.9.8 generates PKCS#1 private keys by default, while
	// OpenSSL 1.0.0 generates PKCS#8 keys. We try both.
	var key *rsa.PrivateKey
	if key, err = x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes); err != nil {
		var privKey interface{}
		if privKey, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes); err != nil {
			err = errors.New("crypto/tls: failed to parse key: " + err.Error())
			return
		}

		var ok bool
		if key, ok = privKey.(*rsa.PrivateKey); !ok {
			err = errors.New("crypto/tls: found non-RSA private key in PKCS#8 wrapping")
			return
		}
	}
	cert.PrivateKey = key
	return
}
