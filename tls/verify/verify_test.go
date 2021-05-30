package verify

import (
	"errors"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	grpcServer_AddrDirect        = "localhost:10001"
	grpcServer_SelfsignedOK      = "localhost:10010"
	grpcServer_SelfsignedExpired = "localhost:10020"
	grpcServer_SelfsignedSimple  = "localhost:10030"
	grpcServer_trustedOK         = "localhost:10040"
	grpcServer_trustedExpired    = "localhost:10050"

	httpServer_AddrDirect        = "localhost:10002"
	httpServer_SelfsignedOK      = "localhost:10110"
	httpServer_SelfsignedExpired = "localhost:10120"
	httpServer_SelfsignedSimple  = "localhost:10130"
	httpServer_trustedOK         = "localhost:10140"
	httpServer_trustedExpired    = "localhost:10150"
)

func TestHTTP_Trusted(t *testing.T) {
	want := "ok"
	t.Run("fingerprintOK", func(t *testing.T) {
		c := HttpClient(FingerprintSHA1("EE:28:78:56:84:05:B3:11:CD:F1:78:D7:5A:65:92:56:7D:82:9F:1E"))
		res, err := c.Get("https://" + httpServer_trustedOK + "?query=" + want)
		assert.NoError(t, err)
		dat, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		assert.NoError(t, err)
		assert.EqualValues(t, want, string(dat))
	})
	t.Run("fingerprintInvalid", func(t *testing.T) {
		c := HttpClient(FingerprintSHA1("81f344a7686a80b4c5293e8fdc0b0160c82c06a8"))
		_, err := c.Get("https://" + httpServer_trustedOK + "?query=ok")
		assert.Error(t, err)
		assert.EqualError(t, errors.Unwrap(err), ErrNotMatchedFingerprint.Error())
	})
	t.Run("expired", func(t *testing.T) {
		c := HttpClient()
		_, err := c.Get("https://" + httpServer_trustedExpired + "?query=ok")
		assert.Error(t, err)
		assert.EqualError(t, errors.Unwrap(err), ErrCertExpired.Error())
	})
	t.Run("lifetimeCheckedFirst", func(t *testing.T) {
		c := HttpClient(FingerprintSHA1("81f344a7686a80b4c5293e8fdc0b0160c82c06a8"))
		_, err := c.Get("https://" + httpServer_trustedExpired + "?query=ok")
		assert.Error(t, err)
		assert.EqualError(t, errors.Unwrap(err), ErrCertExpired.Error())
	})
}

func TestHTTP_Selfsigned(t *testing.T) {
	want := "ok"
	t.Run("unknownAuthority", func(t *testing.T) {
		c := HttpClient()
		_, err := c.Get("https://" + httpServer_SelfsignedOK + "?query=ok")
		assert.Error(t, err)
		assert.EqualError(t, errors.Unwrap(err), "x509: certificate signed by unknown authority")

	})
	t.Run("fingerprintOK", func(t *testing.T) {
		c := HttpClient(
			FingerprintSHA1("87:CB:7E:A9:55:BE:E6:D3:A8:B8:29:05:ED:6A:10:FE:D2:62:62:E8"),
			SkipTLSVerify(),
		)
		res, err := c.Get("https://" + httpServer_SelfsignedOK + "?query=" + want)
		assert.NoError(t, err)
		dat, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		assert.NoError(t, err)
		assert.EqualValues(t, want, string(dat))
	})
	t.Run("fingerprintInvalid", func(t *testing.T) {
		c := HttpClient(
			FingerprintSHA1("81f344a7686a80b4c5293e8fdc0b0160c82c06a8"),
			SkipTLSVerify(),
		)
		_, err := c.Get("https://" + httpServer_SelfsignedOK + "?query=" + want)
		assert.Error(t, err)
		assert.EqualError(t, errors.Unwrap(err), ErrNotMatchedFingerprint.Error())
	})
	t.Run("ok", func(t *testing.T) {
		c := HttpClient(
			SkipTLSVerify(),
		)
		res, err := c.Get("https://" + httpServer_SelfsignedOK + "?query=" + want)
		assert.NoError(t, err)
		dat, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		assert.NoError(t, err)
		assert.EqualValues(t, want, string(dat))
	})
	t.Run("expired", func(t *testing.T) {
		c := HttpClient(
			SkipTLSVerify(),
		)
		res, err := c.Get("https://" + httpServer_SelfsignedExpired + "?query=" + want)
		assert.NoError(t, err)
		dat, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		assert.NoError(t, err)
		assert.EqualValues(t, want, string(dat))
	})
}
