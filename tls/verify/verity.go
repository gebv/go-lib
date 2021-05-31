package verify

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	internalErrors "github.com/gebv/go-lib/internal/errors"
	"github.com/pion/dtls/pkg/crypto/fingerprint"
	"github.com/pkg/errors"
)

var (
	ErrCertExpired           = errors.New("certificate expired")
	ErrNotMatchedFingerprint = errors.New("not matched fingerprint")
)

func TLSVerifyPeerCertificate(opts ...tlsVerifyPeerCertificateOption) *tlsVerifyPeerCertificate {
	v := &tlsVerifyPeerCertificate{
		opts:    &tlsVerifyPeerCertificateOptions{},
		waitErr: internalErrors.WaitOneErrorOrNil(),
	}
	for _, set := range opts {
		set(v.opts)
	}
	return v
}

func TLSVerifyPeerCertificateWithContext(ctx context.Context, opts ...tlsVerifyPeerCertificateOption) (*tlsVerifyPeerCertificate, context.Context) {
	w, ctx := internalErrors.WaitOneErrorOrNilWithontext(ctx)
	v := &tlsVerifyPeerCertificate{
		opts:    &tlsVerifyPeerCertificateOptions{},
		waitErr: w,
	}
	for _, set := range opts {
		set(v.opts)
	}
	return v, ctx
}

type tlsVerifyPeerCertificate struct {
	opts    *tlsVerifyPeerCertificateOptions
	waitErr interface {
		Wait() error
		Release(err error)
	}
}

func (v *tlsVerifyPeerCertificate) Wait() error {
	if v.waitErr == nil {
		return errors.New("error waiter in nil")
	}
	return v.waitErr.Wait()
}

func (v *tlsVerifyPeerCertificate) Option() func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		defer v.releaseDone()

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
			gotFingerprint, err := fingerprint.Fingerprint(certs[0], crypto.SHA1)
			if err != nil {
				err = errors.Wrap(err, "failed to create a fingerprint for server cert")
				v.releaseError(err)
				return err
			}
			if normalHex(v.opts.SHA1Fingerprint) != normalHex(gotFingerprint) {
				err := ErrNotMatchedFingerprint
				v.releaseError(err)
				return err
			}
		}

		return nil
	}
}

func (v *tlsVerifyPeerCertificate) releaseError(err error) {
	if v.waitErr != nil {
		v.waitErr.Release(err)
	}
}

func (v *tlsVerifyPeerCertificate) releaseDone() {
	if v.waitErr != nil {
		v.waitErr.Release(nil)
	}
}
