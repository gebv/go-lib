package verify

type VerifyPeerCertificateOption func(opts *verifyPeerCertificateOptions)

type verifyPeerCertificateOptions struct {
	SkipTLSVerify   bool
	DNSName         string
	SHA1Fingerprint string
	EventChan       chan Event
}

func Events(ch chan Event) VerifyPeerCertificateOption {
	return func(opts *verifyPeerCertificateOptions) {
		opts.EventChan = ch
	}
}

func SkipTLSVerify() VerifyPeerCertificateOption {
	return func(opts *verifyPeerCertificateOptions) {
		opts.SkipTLSVerify = true
	}
}

func FingerprintSHA1(sha1hex string) VerifyPeerCertificateOption {
	return func(opts *verifyPeerCertificateOptions) {
		opts.SHA1Fingerprint = sha1hex
	}
}

func DNSName(dnsName string) VerifyPeerCertificateOption {
	return func(opts *verifyPeerCertificateOptions) {
		opts.DNSName = dnsName
	}
}

func (o verifyPeerCertificateOptions) sendEvent(e Event) {
	if o.EventChan == nil {
		return
	}
	select {
	case o.EventChan <- e:
	default:
	}
}

type Event interface {
	isEvent()
}

type Event_Begin struct{}

func (Event_Begin) isEvent() {}

var _ Event = (*Event_Begin)(nil)

type Event_Done struct{}

func (Event_Done) isEvent() {}

var _ Event = (*Event_Done)(nil)

type Event_Err struct {
	Err error
}

func (Event_Err) isEvent() {}

var _ Event = (*Event_Err)(nil)
