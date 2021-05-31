package verify

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	pb "github.com/gebv/go-lib/tls/verify/testdata/api/services/simple"
	"github.com/gebv/grpc-conn-err-human-msg/grpcx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

const fingerprintInvalid = "FA:06:9E:6B:79:60:CF:6F:C8:72:1C:04:32:9D:34:77:D8:6C:EA:2E"

func checkRequest(t *testing.T, conn *grpc.ClientConn) {
	t.Helper()
	client := pb.NewSimpleServiceClient(conn)
	res, err := client.Echo(context.TODO(), &pb.EchoRequest{In: "abc"})
	assert.NoError(t, err)
	assert.EqualValues(t, `in:"abc"`, res.GetOut())
}

func TestDirect(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithInsecure())
		opts = append(opts, grpc.WithTimeout(1*time.Second))
		opts = append(opts, grpc.WithBlock())

		ctx := context.Background()

		conn, _, err := grpcx.Dial(ctx, "localhost:10001", time.Second, grpcx.PlainText(), grpcx.AddStdGRPCOptions(opts...))
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()
		checkRequest(t, conn)
	})

}

func TestNoConnect(t *testing.T) {
	refused := "localhost:12312"
	timeout := "10.9.8.7:12312"
	t.Run("refused", func(t *testing.T) {
		t.Parallel()

		t.Run("insecure-plaintext", func(t *testing.T) {
			t.Parallel()

			var opts []grpc.DialOption
			opts = append(opts, grpc.WithInsecure())
			opts = append(opts, grpc.WithTimeout(1*time.Second))
			opts = append(opts, grpc.WithBlock())

			ctx := context.Background()

			_, _, err := grpcx.Dial(ctx, refused, time.Second, grpcx.PlainText(), grpcx.AddStdGRPCOptions(opts...))
			assert.Error(t, err)
		})

		t.Run("tls", func(t *testing.T) {
			t.Parallel()

			var opts []grpc.DialOption
			opts = append(opts, grpc.WithTimeout(1*time.Second))
			opts = append(opts, grpc.WithBlock())

			ctx := context.Background()

			_, _, err := grpcx.Dial(ctx, refused, time.Second, grpcx.AddStdGRPCOptions(opts...))
			assert.Error(t, err)
		})

		t.Run("skiptlsverify", func(t *testing.T) {
			t.Parallel()

			var opts []grpc.DialOption
			opts = append(opts, grpc.WithTimeout(1*time.Second))
			opts = append(opts, grpc.WithBlock())

			ctx := context.Background()

			_, _, err := grpcx.Dial(ctx, refused, time.Second, grpcx.SkipTLSVerify(), grpcx.AddStdGRPCOptions(opts...))
			assert.Error(t, err)
		})
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		t.Run("insecure-plaintext", func(t *testing.T) {
			t.Parallel()
			var opts []grpc.DialOption
			opts = append(opts, grpc.WithInsecure())
			opts = append(opts, grpc.WithTimeout(1*time.Second))
			opts = append(opts, grpc.WithBlock())

			ctx := context.Background()

			_, _, err := grpcx.Dial(ctx, timeout, time.Second, grpcx.PlainText(), grpcx.AddStdGRPCOptions(opts...))
			assert.Error(t, err)
		})

		t.Run("tls", func(t *testing.T) {
			t.Parallel()
			var opts []grpc.DialOption
			opts = append(opts, grpc.WithTimeout(1*time.Second))
			opts = append(opts, grpc.WithBlock())

			ctx := context.Background()

			_, _, err := grpcx.Dial(ctx, timeout, time.Second, grpcx.AddStdGRPCOptions(opts...))
			assert.Error(t, err)
		})

		t.Run("skiptlsverify", func(t *testing.T) {
			t.Parallel()
			var opts []grpc.DialOption
			opts = append(opts, grpc.WithTimeout(1*time.Second))
			opts = append(opts, grpc.WithBlock())

			ctx := context.Background()

			_, _, err := grpcx.Dial(ctx, timeout, time.Second, grpcx.SkipTLSVerify(), grpcx.AddStdGRPCOptions(opts...))
			assert.Error(t, err)
		})
	})

}

func TestSSLOK(t *testing.T) {
	addr := "localhost:10010"
	fingerprintOK := "1F:91:6F:41:62:AE:5A:F7:3F:96:94:55:A2:25:26:03:AA:AB:3B:61"

	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		conn, _, err := grpcx.Dial(ctx, addr, time.Second, grpcx.SkipTLSVerify(), grpcx.AddStdGRPCOptions(opts...))
		if err != nil {
			t.Fatalf("fail to dial: %v", err)
		}

		defer conn.Close()
		conn.GetState()
		checkRequest(t, conn)
	})

	t.Run("fingerprintOK", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		conn, _, err := grpcx.Dial(ctx, addr, time.Second,
			grpcx.SkipTLSVerify(),
			grpcx.Fingerprint(fingerprintOK),
			grpcx.AddStdGRPCOptions(opts...))
		if err != nil {
			t.Fatalf("fail to dial: %v", err)
		}

		defer conn.Close()
		conn.GetState()
		checkRequest(t, conn)
	})

	t.Run("withoutSkipTLSVerify", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		_, _, err := grpcx.Dial(ctx, addr, time.Second, grpcx.AddStdGRPCOptions(opts...))
		assert.Error(t, err)
	})

	t.Run("fingerprintInvalid", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		_, _, err := grpcx.Dial(ctx, addr, time.Second,
			grpcx.SkipTLSVerify(),
			grpcx.Fingerprint(fingerprintInvalid),
			grpcx.AddStdGRPCOptions(opts...))
		assert.Error(t, err)
	})

	t.Run("withoutSkipTLSVerify-fingerprintOK", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		_, _, err := grpcx.Dial(ctx, addr, time.Second,
			grpcx.Fingerprint(fingerprintOK),
			grpcx.AddStdGRPCOptions(opts...))
		assert.Error(t, err)
	})

	t.Run("withoutSkipTLSVerify-fingerprintInvalid", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		_, _, err := grpcx.Dial(ctx, addr, time.Second,
			grpcx.Fingerprint(fingerprintInvalid),
			grpcx.AddStdGRPCOptions(opts...))
		assert.Error(t, err)
	})
}

func TestSSLExpired(t *testing.T) {
	addr := "localhost:10020"
	fingerprintOK := "7E:12:49:9C:EC:EC:22:DE:53:78:71:79:BF:28:D4:51:2D:66:23:96"

	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		conn, _, err := grpcx.Dial(ctx, addr, time.Second, grpcx.SkipTLSVerify(), grpcx.AddStdGRPCOptions(opts...))
		if err != nil {
			t.Fatalf("fail to dial: %v", err)
		}

		defer conn.Close()
		conn.GetState()
		checkRequest(t, conn)
	})
	t.Run("fingerprintOK", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		conn, _, err := grpcx.Dial(ctx, addr, time.Second,
			grpcx.SkipTLSVerify(),
			grpcx.Fingerprint(fingerprintOK),
			grpcx.AddStdGRPCOptions(opts...))
		if err != nil {
			t.Fatalf("fail to dial: %v", err)
		}

		defer conn.Close()
		conn.GetState()
		checkRequest(t, conn)
	})

	t.Run("fingerprintInvalid", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		_, _, err := grpcx.Dial(ctx, addr, time.Second,
			grpcx.SkipTLSVerify(),
			grpcx.Fingerprint(fingerprintInvalid),
			grpcx.AddStdGRPCOptions(opts...))
		assert.Error(t, err)
	})

	t.Run("withoutSkipTLSVerify", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		_, _, err := grpcx.Dial(ctx, addr, time.Second, grpcx.AddStdGRPCOptions(opts...))
		assert.Error(t, err)
	})

	t.Run("withoutSkipTLSVerify-fingerprintOK", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		_, _, err := grpcx.Dial(ctx, addr, time.Second,
			grpcx.Fingerprint(fingerprintOK),
			grpcx.AddStdGRPCOptions(opts...))
		assert.Error(t, err)
	})

	t.Run("withoutSkipTLSVerify-fingerprintInvalid", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		_, _, err := grpcx.Dial(ctx, addr, time.Second,
			grpcx.Fingerprint(fingerprintInvalid),
			grpcx.AddStdGRPCOptions(opts...))
		assert.Error(t, err)
	})
}

func TestTrustedRootCA(t *testing.T) {
	addr := "localhost:10040"
	fingerprintOK := FingerprintServerCert(t, addr)
	require.NotEmpty(t, fingerprintOK)

	t.Run("skipVerifyTLS", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		conn, _, err := grpcx.Dial(ctx, addr, time.Second, grpcx.SkipTLSVerify(), grpcx.AddStdGRPCOptions(opts...))
		if err != nil {
			t.Fatalf("fail to dial: %v", err)
		}

		defer conn.Close()
		conn.GetState()
		checkRequest(t, conn)
	})
	t.Run("withVerifyTLS", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		conn, _, err := grpcx.Dial(ctx, addr, time.Second,
			grpcx.AddStdGRPCOptions(opts...))
		if err != nil {
			t.Fatalf("fail to dial: %v", err)
		}

		defer conn.Close()
		conn.GetState()
		checkRequest(t, conn)
	})
	t.Run("withVerifyTLS-fingerprintOK", func(t *testing.T) {
		t.Parallel()
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithTimeout(1*time.Second))

		ctx := context.Background()

		conn, _, err := grpcx.Dial(ctx, addr, time.Second,
			grpcx.Fingerprint(fingerprintOK),
			grpcx.AddStdGRPCOptions(opts...))
		if err != nil {
			t.Fatalf("fail to dial: %v", err)
		}

		defer conn.Close()
		conn.GetState()
		checkRequest(t, conn)
	})
}

func FingerprintServerCert(t *testing.T, addr string) string {
	t.Helper()

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Error("failed connect to addr", err)
		return ""
	}
	defer conn.Close()
	if len(conn.ConnectionState().PeerCertificates) > 0 {
		return fmt.Sprintf("%x", sha1.Sum(conn.ConnectionState().PeerCertificates[0].Raw))
	}
	t.Log("Without certs")
	return ""
}
