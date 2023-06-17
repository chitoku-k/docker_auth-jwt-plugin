package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
)

func httpClientWithRootCA(httpClient *http.Client, caPath string) (*http.Client, error) {
	var tr *http.Transport
	if httpClient.Transport == nil {
		tr = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		tr = httpClient.Transport.(*http.Transport).Clone()
	}

	caPem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	tr.TLSClientConfig.RootCAs = x509.NewCertPool()
	tr.TLSClientConfig.RootCAs.AppendCertsFromPEM(caPem)

	newHTTPClient := *httpClient
	newHTTPClient.Transport = tr
	return &newHTTPClient, nil
}
