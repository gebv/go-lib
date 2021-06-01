package verify

import (
	"crypto/tls"
	"net/http"
)

func HttpClient(opts ...VerifyPeerCertificateOption) *http.Client {
	v := VerifyPeerCertificate(opts...)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify:    true,
				VerifyPeerCertificate: v.Option(),
			},
		},
	}
}
