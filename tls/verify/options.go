package verify

type tlsVerifyPeerCertificateOption func(opts *tlsVerifyPeerCertificateOptions)

type tlsVerifyPeerCertificateOptions struct {
	SkipTLSVerify   bool
	DNSName         string
	SHA1Fingerprint string
}

func SkipTLSVerify() tlsVerifyPeerCertificateOption {
	return func(opts *tlsVerifyPeerCertificateOptions) {
		opts.SkipTLSVerify = true
	}
}

func FingerprintSHA1(sha1hex string) tlsVerifyPeerCertificateOption {
	return func(opts *tlsVerifyPeerCertificateOptions) {
		opts.SHA1Fingerprint = sha1hex
	}
}

func DNSName(dnsName string) tlsVerifyPeerCertificateOption {
	return func(opts *tlsVerifyPeerCertificateOptions) {
		opts.DNSName = dnsName
	}
}
