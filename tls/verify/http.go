package verify

import (
	"crypto/tls"
	"net/http"
)

func HttpClient(opts ...tlsVerifyPeerCertificateOption) *http.Client {
	v := TLSVerifyPeerCertificate(opts...)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify:    true,
				VerifyPeerCertificate: v.Option(),
			},
		},
	}
}
