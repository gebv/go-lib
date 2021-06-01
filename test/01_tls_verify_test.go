package test

import (
	"context"
	"errors"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	pb "github.com/gebv/go-lib/test/testdata/verify/api/services/simple"
	"github.com/gebv/go-lib/tls/verify"
	grpcx "github.com/gebv/go-lib/tls/verify/grpc"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

const (
	grpcServer_Direct            = "localhost:10001"
	grpcServer_SelfsignedOK      = "localhost:10010"
	grpcServer_SelfsignedExpired = "localhost:10020"
	grpcServer_SelfsignedSimple  = "localhost:10030"
	grpcServer_trustedOK         = "localhost:10040"
	grpcServer_trustedExpired    = "localhost:10050"

	httpServer_Direct            = "localhost:10002"
	httpServer_SelfsignedOK      = "localhost:10110"
	httpServer_SelfsignedExpired = "localhost:10120"
	httpServer_SelfsignedSimple  = "localhost:10130"
	httpServer_trustedOK         = "localhost:10140"
	httpServer_trustedExpired    = "localhost:10150"

	selfsignedOK_CertFileFingerprint      = "testdata/verify/ssl/selfsigned-localhost-ok.crt.sha1"
	selfsignedExpired_CertFileFingerprint = "testdata/verify/ssl/selfsigned-localhost-expired.crt.sha1"
	selfsignedSimple_CertFileFingerprint  = "testdata/verify/ssl/selfsigned-localhost-simple.crt.sha1"
	trustedOK_CertFileFingerprint         = "testdata/verify/ssl/trusted-localhost-ok.crt.sha1"
	trustedExpired_CertFileFingerprint    = "testdata/verify/ssl/trusted-localhost-expired.crt.sha1"

	fingerprintNoRegistred = "81f344a7686a80b4c5293e8fdc0b0160c82c06a8"
)

var mapAddrToCert = map[string]string{
	grpcServer_SelfsignedOK:      selfsignedOK_CertFileFingerprint,
	grpcServer_SelfsignedExpired: selfsignedExpired_CertFileFingerprint,
	grpcServer_SelfsignedSimple:  selfsignedSimple_CertFileFingerprint,
	grpcServer_trustedOK:         trustedOK_CertFileFingerprint,
	grpcServer_trustedExpired:    trustedExpired_CertFileFingerprint,
	httpServer_SelfsignedOK:      selfsignedOK_CertFileFingerprint,
	httpServer_SelfsignedExpired: selfsignedExpired_CertFileFingerprint,
	httpServer_SelfsignedSimple:  selfsignedSimple_CertFileFingerprint,
	httpServer_trustedOK:         trustedOK_CertFileFingerprint,
	httpServer_trustedExpired:    trustedExpired_CertFileFingerprint,
}

func extractFingerptinSHA1(t *testing.T, addr string) string {
	filePath, exists := mapAddrToCert[addr]
	if !exists {
		t.Fatal("not found pre-stored cert for addr:", addr)
	}
	dat, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed read file %q: %v", filePath, err)
	}
	const prefix = "SHA1 Fingerprint="
	if !strings.HasPrefix(string(dat), prefix) {
		t.Fatalf("failed format file %q - should start with '"+prefix+"': %q", filePath, string(dat))
	}
	sha1hex := string(dat)[len(prefix):]
	if len(sha1hex) == 0 {
		t.Fatalf("empty sha1 for cert %q", filePath)
	}
	sha1hex = strings.TrimSpace(sha1hex)
	t.Logf("fingerprint %q for %q", sha1hex, addr)
	return sha1hex
}

func TestTLSVerify_HTTP_Trusted(t *testing.T) {
	want := "ok"
	t.Run("fingerprintOK", func(t *testing.T) {
		addr := httpServer_trustedOK
		addrFingerprint := extractFingerptinSHA1(t, addr)

		c := verify.HttpClient(verify.FingerprintSHA1(addrFingerprint))

		res, err := c.Get("https://" + addr + "?query=" + want)
		assert.NoError(t, err)

		dat, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		assert.NoError(t, err)
		assert.EqualValues(t, want, string(dat))
	})
	t.Run("fingerprintInvalid", func(t *testing.T) {
		c := verify.HttpClient(verify.FingerprintSHA1(fingerprintNoRegistred))
		_, err := c.Get("https://" + httpServer_trustedOK + "?query=ok")
		assert.Error(t, err)
		assert.EqualError(t, errors.Unwrap(err), verify.ErrNotMatchedFingerprint.Error())
	})
	t.Run("expired", func(t *testing.T) {
		c := verify.HttpClient()
		_, err := c.Get("https://" + httpServer_trustedExpired + "?query=ok")
		assert.Error(t, err)
		assert.EqualError(t, errors.Unwrap(err), verify.ErrCertExpired.Error())
	})
	t.Run("lifetimeCheckedFirst", func(t *testing.T) {
		c := verify.HttpClient(verify.FingerprintSHA1(fingerprintNoRegistred))
		_, err := c.Get("https://" + httpServer_trustedExpired + "?query=ok")
		assert.Error(t, err)
		assert.EqualError(t, errors.Unwrap(err), verify.ErrCertExpired.Error())
	})
}

func TestTLSVerify_HTTP_Selfsigned(t *testing.T) {
	want := "ok"
	t.Run("unknownAuthority", func(t *testing.T) {
		c := verify.HttpClient()
		_, err := c.Get("https://" + httpServer_SelfsignedOK + "?query=ok")
		assert.Error(t, err)
		assert.EqualError(t, errors.Unwrap(err), "x509: certificate signed by unknown authority")

	})
	t.Run("fingerprintOK", func(t *testing.T) {
		addr := httpServer_SelfsignedOK
		addrFingerprint := extractFingerptinSHA1(t, addr)

		c := verify.HttpClient(
			verify.FingerprintSHA1(addrFingerprint),
			verify.SkipTLSVerify(),
		)
		res, err := c.Get("https://" + addr + "?query=" + want)
		assert.NoError(t, err)
		dat, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		assert.NoError(t, err)
		assert.EqualValues(t, want, string(dat))
	})
	t.Run("fingerprintInvalid", func(t *testing.T) {
		c := verify.HttpClient(
			verify.FingerprintSHA1(fingerprintNoRegistred),
			verify.SkipTLSVerify(),
		)
		_, err := c.Get("https://" + httpServer_SelfsignedOK + "?query=" + want)
		assert.Error(t, err)
		assert.EqualError(t, errors.Unwrap(err), verify.ErrNotMatchedFingerprint.Error())
	})
	t.Run("ok", func(t *testing.T) {
		c := verify.HttpClient(
			verify.SkipTLSVerify(),
		)
		res, err := c.Get("https://" + httpServer_SelfsignedOK + "?query=" + want)
		assert.NoError(t, err)
		dat, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		assert.NoError(t, err)
		assert.EqualValues(t, want, string(dat))
	})
	t.Run("expired", func(t *testing.T) {
		c := verify.HttpClient(
			verify.SkipTLSVerify(),
		)
		res, err := c.Get("https://" + httpServer_SelfsignedExpired + "?query=" + want)
		assert.NoError(t, err)
		// NOTE: why ok? Because skip the verify cert
		dat, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		assert.NoError(t, err)
		assert.EqualValues(t, want, string(dat))
	})
}

func TestTLSVerify_GRPC_Direct(t *testing.T) {
	t.Run("plaintext", func(t *testing.T) {
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithInsecure())
		opts = append(opts, grpc.WithTimeout(1*time.Second))
		opts = append(opts, grpc.WithBlock())

		ctx := context.Background()
		addr := grpcServer_Direct
		conn, err := grpcx.Dial(ctx, addr,
			grpcx.PlainText(),
			grpcx.AddStdGRPCOptions(opts...),
		)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()
		checkRequest(t, conn)
	})
	t.Run("no-ssl", func(t *testing.T) {
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithTimeout(1*time.Second))
		opts = append(opts, grpc.WithBlock())

		ctx := context.Background()
		addr := grpcServer_Direct
		_, err := grpcx.Dial(ctx, addr,
			grpcx.AddStdGRPCOptions(opts...),
		)
		assert.Error(t, err)
		assert.EqualError(t, err, grpcx.ErrNotResponse.Error())
	})
}

func TestTLSVerify_GRPC_Trusted(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithTimeout(1*time.Second))
		opts = append(opts, grpc.WithBlock())

		ctx := context.Background()
		addr := grpcServer_trustedOK
		conn, err := grpcx.Dial(ctx, addr,
			grpcx.AddStdGRPCOptions(opts...),
		)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()
		checkRequest(t, conn)
	})
	t.Run("okAndFingerprintOK", func(t *testing.T) {
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithTimeout(1*time.Second))
		opts = append(opts, grpc.WithBlock())

		ctx := context.Background()
		addr := grpcServer_trustedOK
		addrFingerprint := extractFingerptinSHA1(t, addr)

		conn, err := grpcx.Dial(ctx, addr,
			grpcx.Fingerprint(addrFingerprint),
			grpcx.AddStdGRPCOptions(opts...),
		)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()
		checkRequest(t, conn)
	})
	t.Run("okAndFingerprintFail", func(t *testing.T) {
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithTimeout(1*time.Second))
		opts = append(opts, grpc.WithBlock())

		ctx := context.Background()
		addr := grpcServer_trustedOK

		_, err := grpcx.Dial(ctx, addr,
			grpcx.Fingerprint(fingerprintNoRegistred),
			grpcx.AddStdGRPCOptions(opts...),
		)
		assert.EqualError(t, err, verify.ErrNotMatchedFingerprint.Error())
	})
	t.Run("expired", func(t *testing.T) {
		addr := grpcServer_trustedExpired
		assertGrpcFailedConn(t, addr, verify.ErrCertExpired)
	})
}

func TestTLSVerify_GRPC_timeout(t *testing.T) {
	refused := "localhost:12312"
	timeout := "10.9.8.7:12312"
}

func assertGrpcFailedConn(t *testing.T, addr string, wantErr error, opts ...grpc.DialOption) {
	if opts == nil || len(opts) == 0 {
		opts = []grpc.DialOption{}
	}
	opts = append(opts, grpc.WithTimeout(1*time.Second))
	opts = append(opts, grpc.WithBlock())

	ctx := context.Background()
	_, err := grpcx.Dial(ctx, addr,
		grpcx.AddStdGRPCOptions(opts...),
	)
	assert.Error(t, err)
	assert.EqualError(t, err, wantErr.Error())
}

func checkRequest(t *testing.T, conn *grpc.ClientConn) {
	t.Helper()
	client := pb.NewSimpleServiceClient(conn)
	res, err := client.Echo(context.TODO(), &pb.EchoRequest{In: "abc"})
	assert.NoError(t, err)
	assert.EqualValues(t, `in:"abc"`, res.GetOut())
}
