package verify

import (
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

var (
	ErrCertExpired           = errors.New("certificate expired")
	ErrNotMatchedFingerprint = errors.New("not matched fingerprint")
)

type Verifier interface {
	Option() func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

func VerifyPeerCertificate(opts ...VerifyPeerCertificateOption) *verifyPeerCertificate {
	v := &verifyPeerCertificate{
		opts: &verifyPeerCertificateOptions{},
	}
	for _, set := range opts {
		set(v.opts)
	}
	return v
}

type verifyPeerCertificate struct {
	opts *verifyPeerCertificateOptions
}

func (v *verifyPeerCertificate) Option() func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		defer v.done()
		v.begin()

		opts := x509.VerifyOptions{
			// TODO: add rootCAs
			CurrentTime:   time.Now(),
			DNSName:       v.opts.DNSName,
			Intermediates: x509.NewCertPool(),
		}

		// Coped code from https://github.com/golang/go/blob/1419ca7cead4438c8c9f17d8901aeecd9c72f577/src/crypto/tls/handshake_client.go#L835
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, asn1Data := range rawCerts {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				err = errors.Wrap(err, "failed to parse certificate from server")
				v.releaseError(err)
				return err
			}
			certs[i] = cert
		}

		if !v.opts.SkipTLSVerify {
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := certs[0].Verify(opts)
			certErr := x509.CertificateInvalidError{}
			if errors.As(err, &certErr) {
				switch certErr.Reason {
				case x509.Expired:
					err = ErrCertExpired
					v.releaseError(err)
					return err
				default:
					// not supported reason error
					v.releaseError(err)
					return err
				}
			} else if err != nil {
				// failed TLS verify cert
				v.releaseError(err)
				return err
			}
		}

		if len(v.opts.SHA1Fingerprint) > 0 {
			got := []byte(fmt.Sprintf("%x", sha1.Sum(certs[0].Raw)))
			if normalHex(v.opts.SHA1Fingerprint) != normalHex(string(got)) {
				err := ErrNotMatchedFingerprint
				v.releaseError(err)
				return err
			}
		}

		return nil
	}
}

func (v *verifyPeerCertificate) releaseError(err error) {
	v.opts.sendEvent(Event_Err{err})
}

func (v *verifyPeerCertificate) done() {
	v.opts.sendEvent(Event_Done{})
}

func (v *verifyPeerCertificate) begin() {
	v.opts.sendEvent(Event_Begin{})
}
