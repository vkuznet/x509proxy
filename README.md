# x509proxy

[![Build Status](https://travis-ci.org/vkuznet/x509proxy.svg?branch=master)](https://travis-ci.org/vkuznet/x509proxy)
[![GoDoc](https://godoc.org/github.com/vkuznet/x509proxy?status.svg)](https://godoc.org/github.com/vkuznet/x509proxy)
[![Go Report Card](https://goreportcard.com/badge/github.com/vkuznet/x509proxy)](https://goreportcard.com/report/github.com/vkuznet/x509proxy)

Package to handle X509 proxy certificates.

### Example

```go
import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
    "github.com/vkuznet/x509proxy"
    "os"
)

// load X509 certificates
func Certs() (tls_certs []tls.Certificate) {
	uproxy := os.Getenv("X509_USER_PROXY")
	uckey := os.Getenv("X509_USER_KEY")
	ucert := os.Getenv("X509_USER_CERT")
	log.Println("X509_USER_PROXY", uproxy)
	log.Println("X509_USER_KEY", uckey)
	log.Println("X509_USER_CERT", ucert)
	if len(uproxy) > 0 {
		// use local implementation of LoadX409KeyPair instead of tls one
		x509cert, err := x509proxy.LoadX509Proxy(uproxy)
		if err != nil {
			log.Println("Fail to parser proxy X509 certificate", err)
			return
		}
		tls_certs = []tls.Certificate{x509cert}
	} else if len(uckey) > 0 {
		x509cert, err := tls.LoadX509KeyPair(ucert, uckey)
		if err != nil {
			log.Println("Fail to parser user X509 certificate", err)
			return
		}
		tls_certs = []tls.Certificate{x509cert}
	} else {
		return
	}
	return
}

// HTTP client
func HttpClient() (client *http.Client) {
	// create HTTP client
	certs := Certs()
	log.Println("Number of certificates", len(certs))
	if len(certs) == 0 {
		client = &http.Client{}
		return
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{Certificates: certs,
			InsecureSkipVerify: true},
	}
	log.Println("Create TLSClientConfig")
	client = &http.Client{Transport: tr}
	return
}

// create global HTTP client and re-use it through the code
var client = HttpClient()

// now you http client is ready to use X509 proxy
```
