package grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/gebv/go-lib/tls/verify"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var ErrNotResponse = errors.New("did not receive a response in a reasonable time (maybe forgot to enable Insecure option?")

func Dial(parent context.Context, addr string, sets ...GRPCDialOption) (*grpc.ClientConn, error) {
	opts := GRPCDialOptions{}
	for _, set := range sets {
		set(&opts)
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if opts.TryConnectTimeout > 0 {
		conn, err := net.DialTimeout("tcp", addr, opts.TryConnectTimeout)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
	} else {
		ctx, cancel = context.WithCancel(parent)
	}

	tlsVerifierOpts := []verify.VerifyPeerCertificateOption{}
	if len(opts.Fingerprint) > 0 {
		tlsVerifierOpts = append(tlsVerifierOpts, verify.FingerprintSHA1(opts.Fingerprint))
	}

	if opts.SkipTLSVerify {
		tlsVerifierOpts = append(tlsVerifierOpts, verify.SkipTLSVerify())
	}

	events := make(chan verify.Event)
	tlsVerifierOpts = append(tlsVerifierOpts, verify.Events(events))

	if !opts.PlainText {
		opts.GRPCOptions = append(opts.GRPCOptions,
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				// it is ok we used VerifyPeerCertificate
				InsecureSkipVerify:    true,
				VerifyPeerCertificate: verify.VerifyPeerCertificate(tlsVerifierOpts...).Option(),
			})),
		)
	}

	connOrErr := make(chan dialResult)

	// trying to establish a connection then
	// - or will be an error at the verification stage
	// - or returns a standart errors
	go func() {
		defer close(connOrErr)
		conn, err := grpc.DialContext(ctx, addr, opts.GRPCOptions...)
		connOrErr <- dialResult{conn, err}
	}()

	// upper limit
	timeout := time.Second
	if opts.TryConnectTimeout > 0 {
		timeout = opts.TryConnectTimeout
	}

	defer cancel()
	for {
		select {
		case <-time.After(timeout):
			return nil, ErrNotResponse
		// handle events from verifyer
		case e := <-events:
			switch e := e.(type) {
			case verify.Event_Begin:
			case verify.Event_Done:
			case verify.Event_Err:
				return nil, e.Err
			}
		// handle events from std grpc dialer
		case res, ok := <-connOrErr:
			if !ok {
				return nil, errors.New("no result (should not happen)")
			}
			if res.err != nil {
				return nil, res.err
			}
			if res.conn != nil {
				return res.conn, nil
			}

			panic("something wrong")
		}
	}
}

type dialResult struct {
	conn *grpc.ClientConn
	err  error
}

type GRPCDialOption func(opts *GRPCDialOptions)

type GRPCDialOptions struct {
	TryConnectTimeout time.Duration
	// if true then disabled TLS
	PlainText bool
	// skips certificate verification
	SkipTLSVerify bool
	// if set then checks fingerprint the server cert
	Fingerprint string
	// standart grpc opts
	GRPCOptions []grpc.DialOption
}

// PlainText disables TLS.
func PlainText() GRPCDialOption {
	return func(opts *GRPCDialOptions) {
		opts.PlainText = true
	}
}

// TryConnect before create grpc client connection will try to connect to the addres.
func TryConnect(timeout time.Duration) GRPCDialOption {
	return func(opts *GRPCDialOptions) {
		opts.TryConnectTimeout = timeout
	}
}

// Fingerprint require fingerprint verification.
func Fingerprint(in string) GRPCDialOption {
	return func(opts *GRPCDialOptions) {
		opts.Fingerprint = in
	}
}

// SkipTLSVerify skips certificate verification.
func SkipTLSVerify() GRPCDialOption {
	return func(opts *GRPCDialOptions) {
		opts.SkipTLSVerify = true
	}
}

func AddStdGRPCOptions(std ...grpc.DialOption) GRPCDialOption {
	return func(opts *GRPCDialOptions) {
		opts.GRPCOptions = std
	}
}
