package protocol

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type Config struct {
	Host, Port, ServerName, SNI, Secret, CAPath, CertPath, KeyPath, KeyPass, P12Path, P12Pass string
	CA                                                                                        []byte
	P12Data, CertData, KeyData                                                                []byte
	MinTLS                                                                                    uint16
	Timeout                                                                                   time.Duration
	// SkipHostnameVerification is for operators whose RadSec endpoint does not
	// have a matching SAN. It disables name matching ONLY; the custom verifier
	// still requires a trusted, time-valid server-auth certificate chain.
	SkipHostnameVerification bool
	// Trace receives only fixed-format, sanitized client-side diagnostics. Optional.
	Trace func(string)
}
type Request struct {
	Kind, Username, Password, Status, SessionID, Extra string
	SessionTime                                        uint32
}
type Result struct {
	Code         byte
	Name         string
	TLSVersion   uint16
	Cipher       string
	PeerSubject  string
	Duration     time.Duration
	Attributes   string
	Observations Observations
}

// Observations contains only measurements made during this exchange. Absence of
// a phase means it was not reached; zero is a legitimate completed duration.
type Observations struct {
	Phases                                          map[string]time.Duration
	RequestBytes, ResponseBytes, ResponseAttributes int
	RequestPackets, ResponsePackets                 int
	ConnectionChecks, PeerCerts                     int
	TLSObserved, TLSResumed                         bool
}

func attr(t byte, v []byte) ([]byte, error) {
	if len(v) > 253 {
		return nil, fmt.Errorf("attribute %d too long", t)
	}
	o := []byte{t, byte(len(v) + 2)}
	return append(o, v...), nil
}
func add(dst []byte, t byte, v []byte) ([]byte, error) {
	a, e := attr(t, v)
	return append(dst, a...), e
}
func ParseAttributes(text string) ([]byte, error) {
	return parseExtraAttributes(text)
}
func validateAttrs(p []byte) error {
	for len(p) > 0 {
		if len(p) < 2 || p[1] < 2 || int(p[1]) > len(p) {
			return errors.New("malformed RADIUS attributes")
		}
		p = p[p[1]:]
	}
	return nil
}
func pap(password, secret string, auth []byte) []byte {
	b := []byte(password)
	if len(b) > 128 {
		b = b[:128]
	}
	n := (len(b) + 15) / 16
	if n == 0 {
		n = 1
	}
	out := make([]byte, n*16)
	copy(out, b)
	prior := auth
	for i := 0; i < len(out); i += 16 {
		h := md5.New()
		h.Write([]byte(secret))
		h.Write(prior)
		sum := h.Sum(nil)
		for j := 0; j < 16; j++ {
			out[i+j] ^= sum[j]
		}
		prior = out[i : i+16]
	}
	return out
}
func maOffset(p []byte) int {
	for i := 20; i < len(p); {
		if i+2 > len(p) || p[i+1] < 2 || i+int(p[i+1]) > len(p) {
			return -1
		}
		if p[i] == 80 && p[i+1] == 18 {
			return i + 2
		}
		i += int(p[i+1])
	}
	return -1
}
func macPacket(p, secret []byte, requestAuth []byte) []byte {
	b := append([]byte(nil), p...)
	if requestAuth != nil {
		copy(b[4:20], requestAuth)
	}
	if i := maOffset(b); i >= 0 {
		clear(b[i : i+16])
	}
	h := hmac.New(md5.New, secret)
	h.Write(b)
	return h.Sum(nil)
}
func VerifyMessageAuthenticator(p, secret, requestAuth []byte) bool {
	i := maOffset(p)
	return i >= 0 && hmac.Equal(p[i:i+16], macPacket(p, secret, requestAuth))
}
func build(req Request, secret string) ([]byte, error) {
	if strings.TrimSpace(req.Username) == "" {
		return nil, errors.New("username required")
	}
	if len(req.Username) > 253 {
		return nil, errors.New("username too long")
	}
	if req.Kind == "auth" && (req.Password == "" || len(req.Password) > 128) {
		return nil, errors.New("authentication password required (1..128 bytes)")
	}
	p := make([]byte, 20)
	if _, e := rand.Read(p[4:20]); e != nil {
		return nil, e
	}
	if _, e := rand.Read(p[1:2]); e != nil {
		return nil, e
	}
	if p[1] == 0 {
		p[1] = 1 // ID 0 is reserved for the server connection check.
	}
	var e error
	p, e = add(p, 1, []byte(req.Username))
	if e != nil {
		return nil, e
	}
	switch req.Kind {
	case "auth":
		p[0] = 1
		p, e = add(p, 2, pap(req.Password, secret, p[4:20]))
		if e != nil {
			return nil, e
		}
	case "acct":
		p[0] = 4
		statuses := map[string]uint32{"Start": 1, "Stop": 2, "Interim-Update": 3}
		s, ok := statuses[req.Status]
		if !ok {
			return nil, errors.New("invalid accounting status")
		}
		if req.SessionID == "" {
			return nil, errors.New("session ID required")
		}
		v := make([]byte, 4)
		binary.BigEndian.PutUint32(v, s)
		p, e = add(p, 40, v)
		if e != nil {
			return nil, e
		}
		p, e = add(p, 44, []byte(req.SessionID))
		if e != nil {
			return nil, e
		}
		if req.SessionTime > 0 {
			binary.BigEndian.PutUint32(v, req.SessionTime)
			p, e = add(p, 46, v)
			if e != nil {
				return nil, e
			}
		}
	default:
		return nil, errors.New("invalid test kind")
	}
	extra, e := ParseAttributes(req.Extra)
	if e != nil {
		return nil, e
	}
	if req.Kind == "acct" && req.SessionTime > 0 {
		for i := 0; i < len(extra); i += int(extra[i+1]) {
			if extra[i] == 46 {
				return nil, errors.New("Acct-Session-Time duplicates accounting session seconds")
			}
		}
	}
	p = append(p, extra...)
	if req.Kind == "auth" {
		p, e = add(p, 80, make([]byte, 16))
		if e != nil {
			return nil, e
		}
	}
	if len(p) > 4096 {
		return nil, errors.New("RADIUS packet exceeds 4096 bytes")
	}
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	if req.Kind == "acct" {
		clear(p[4:20])
		h := md5.New()
		h.Write(p)
		h.Write([]byte(secret))
		copy(p[4:20], h.Sum(nil))
	} else {
		copy(p[maOffset(p):], macPacket(p, []byte(secret), nil))
	}
	return p, nil
}
func ReadPacket(r io.Reader) ([]byte, error) {
	p := make([]byte, 20)
	if _, e := io.ReadFull(r, p); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(p[2:4]))
	if n < 20 || n > 4096 {
		return nil, fmt.Errorf("invalid RADIUS length (%d bytes)", n)
	}
	p = append(p, make([]byte, n-20)...)
	_, e := io.ReadFull(r, p[20:])
	if e != nil {
		return nil, e
	}
	if e = validateAttrs(p[20:]); e != nil {
		return nil, e
	}
	return p, nil
}
func MakeResponse(code byte, req, secret, attrs []byte) []byte {
	r := make([]byte, 20)
	r[0] = code
	r[1] = req[1]
	r = append(r, attrs...)
	binary.BigEndian.PutUint16(r[2:4], uint16(len(r)))
	copy(r[4:20], req[4:20])
	h := md5.New()
	h.Write(r)
	h.Write(secret)
	copy(r[4:20], h.Sum(nil))
	return r
}
func verifyResponse(r, req []byte, secret string) error {
	if r[1] != req[1] {
		return fmt.Errorf("RADIUS identifier mismatch (expected %d, received %d)", req[1], r[1])
	}
	if (req[0] == 1 && (r[0] != 2 && r[0] != 3 && r[0] != 11)) || (req[0] == 4 && r[0] != 5) {
		return fmt.Errorf("unexpected RADIUS response code %d", r[0])
	}
	b := append([]byte(nil), r...)
	copy(b[4:20], req[4:20])
	h := md5.New()
	h.Write(b)
	h.Write([]byte(secret))
	if !hmac.Equal(r[4:20], h.Sum(nil)) {
		return errors.New("invalid response authenticator")
	}
	if maOffset(r) >= 0 && !VerifyMessageAuthenticator(r, []byte(secret), req[4:20]) {
		return errors.New("invalid response Message-Authenticator")
	}
	return nil
}
func loadCert(c Config) (tls.Certificate, error) {
	cert, key := c.CertData, c.KeyData
	if len(cert) == 0 || len(key) == 0 {
		var e error
		cert, e = os.ReadFile(c.CertPath)
		if e != nil {
			return tls.Certificate{}, e
		}
		key, e = os.ReadFile(c.KeyPath)
		if e != nil {
			return tls.Certificate{}, e
		}
	}
	if c.KeyPass != "" {
		var rest, out []byte
		rest = key
		for len(rest) > 0 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if x509.IsEncryptedPEMBlock(block) {
				der, err := x509.DecryptPEMBlock(block, []byte(c.KeyPass))
				if err != nil {
					return tls.Certificate{}, fmt.Errorf("private key passphrase: %w", err)
				}
				block = &pem.Block{Type: block.Type, Bytes: der}
			}
			out = append(out, pem.EncodeToMemory(block)...)
		}
		key = out
	}
	return tls.X509KeyPair(cert, key)
}
func loadP12(c Config) (tls.Certificate, error) {
	data := c.P12Data
	if len(data) == 0 {
		var err error
		data, err = os.ReadFile(c.P12Path)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("read P12 file: %w", err)
		}
	}
	key, leaf, chain, err := pkcs12.DecodeChain(data, c.P12Pass)
	if err != nil {
		return tls.Certificate{}, errors.New("unable to decode P12 client certificate (check file and password)")
	}
	cert := tls.Certificate{PrivateKey: key, Leaf: leaf, Certificate: [][]byte{leaf.Raw}}
	for _, extra := range chain {
		cert.Certificate = append(cert.Certificate, extra.Raw)
	}
	return cert, nil
}
func Exchange(c Config, q Request) (Result, error) {
	return ExchangeContext(context.Background(), c, q)
}

// ExchangeContext cancels dial, TLS handshake, and packet I/O without weakening verification.
func ExchangeContext(ctx context.Context, c Config, q Request) (res Result, e error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	start := time.Now()
	res.Observations.Phases = make(map[string]time.Duration)
	mark := func(name string, began time.Time) { res.Observations.Phases[name] = time.Since(began) }
	prepStart := time.Now()
	trace := func(stage string) {
		if c.Trace != nil {
			c.Trace(fmt.Sprintf("%s · %d ms", stage, time.Since(start).Milliseconds()))
		}
	}
	trace("Client-side request preparation started")

	secret := c.Secret
	if secret == "" {
		return res, errors.New("shared secret required")
	}
	p, e := build(q, secret)
	if e != nil {
		return res, e
	}
	trace(fmt.Sprintf("RADIUS request built: code %d, ID %d, length %d bytes; attribute values hidden", p[0], p[1], len(p)))
	trace("TLS trust store loading")
	roots, e := x509.SystemCertPool()
	if e != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	ca := c.CA
	if c.CAPath != "" {
		ca, e = os.ReadFile(c.CAPath)
		if e != nil {
			return res, e
		}
	}
	if len(ca) > 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return res, errors.New("invalid CA PEM")
		}
	}
	name := c.ServerName
	if name == "" && !c.SkipHostnameVerification {
		name = c.Host
	}
	if c.SNI != "" && c.ServerName != "" && c.SNI != c.ServerName && !c.SkipHostnameVerification {
		return res, errors.New("SNI and verification name must match (custom SNI with separate verification unsupported)")
	}
	if c.SNI != "" {
		name = c.SNI
	}
	v := c.MinTLS
	if v == 0 {
		v = tls.VersionTLS12
	}
	if v != tls.VersionTLS12 && v != tls.VersionTLS13 {
		return res, errors.New("minimum TLS must be 1.2 or 1.3")
	}
	tc := &tls.Config{RootCAs: roots, ServerName: name, MinVersion: v}
	if c.SkipHostnameVerification {
		// Go's built-in verifier always checks the hostname. Disable ONLY that
		// verifier and replace it with explicit chain, validity and EKU checks.
		// Never leave InsecureSkipVerify without an equivalent trust callback.
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("TLS server sent no certificate")
			}
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots: roots, Intermediates: intermediates,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			return err
		}
	}
	if (c.P12Path != "" || len(c.P12Data) != 0) && (c.CertPath != "" || c.KeyPath != "" || len(c.CertData) != 0 || len(c.KeyData) != 0 || (c.P12Path != "" && len(c.P12Data) != 0)) {
		return res, errors.New("P12 client certificate and PEM certificate/key paths are mutually exclusive")
	}
	if c.P12Path != "" || len(c.P12Data) != 0 {
		trace("TLS client credential loading: P12")
		crt, err := loadP12(c)
		if err != nil {
			return res, err
		}
		tc.Certificates = []tls.Certificate{crt}
	} else if c.CertPath != "" || c.KeyPath != "" || len(c.CertData) != 0 || len(c.KeyData) != 0 {
		if (c.CertPath == "" || c.KeyPath == "") && (len(c.CertData) == 0 || len(c.KeyData) == 0) {
			return res, errors.New("both client certificate and key required")
		}
		trace("TLS client credential loading: PEM")
		crt, err := loadCert(c)
		if err != nil {
			return res, err
		}
		tc.Certificates = []tls.Certificate{crt}
	}
	if len(tc.Certificates) != 0 {
		// A certificate explicitly chosen by the operator must be offered on
		// CertificateRequest. Go's automatic selection silently sends an empty
		// Certificate when the server advertises unrelated acceptable CA names.
		// The server still verifies or rejects the certificate it receives.
		selected := &tc.Certificates[0]
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return selected, nil
		}
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	mark("prepare", prepStart)
	trace("TCP connect and TLS handshake started")
	d := net.Dialer{Timeout: timeout}
	dialStart := time.Now()
	raw, e := d.DialContext(ctx, "tcp", net.JoinHostPort(c.Host, c.Port))
	mark("tcp dial", dialStart)
	if e != nil {
		trace("TCP/TLS handshake failed: " + traceFailure(e))
		return res, e
	}
	conn := tls.Client(raw, tc)
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { raw.Close() })
	defer stopClose()
	handshakeStart := time.Now()
	e = conn.HandshakeContext(ctx)
	mark("tls handshake", handshakeStart)
	if e != nil {
		trace("TCP/TLS handshake failed: " + traceFailure(e))
		return res, e
	}
	if e = ctx.Err(); e != nil {
		return res, e
	}
	trace("TLS handshake and server certificate verification succeeded")
	conn.SetDeadline(time.Now().Add(timeout))
	state := conn.ConnectionState()
	res.TLSVersion = state.Version
	res.Cipher = tls.CipherSuiteName(state.CipherSuite)
	res.Observations.TLSObserved = true
	res.Observations.TLSResumed = state.DidResume
	res.Observations.PeerCerts = len(state.PeerCertificates)
	trace(fmt.Sprintf("TLS negotiated version 0x%04x, cipher 0x%04x, mutual TLS offered %t", state.Version, state.CipherSuite, len(tc.Certificates) > 0))
	if len(state.PeerCertificates) > 0 {
		res.PeerSubject = state.PeerCertificates[0].Subject.String()
		leaf := state.PeerCertificates[0]
		fingerprint := sha256.Sum256(leaf.Raw)
		trace(fmt.Sprintf("TLS server leaf: SHA-256 %x, validity %s to %s UTC, chain certificates %d; subject and SAN hidden", fingerprint, leaf.NotBefore.UTC().Format("2006-01-02"), leaf.NotAfter.UTC().Format("2006-01-02"), len(state.PeerCertificates)))
	}
	trace("RADIUS request send started")
	writeStart := time.Now()
	var written int
	written, e = conn.Write(p)
	mark("request write", writeStart)
	res.Observations.RequestBytes = written
	if e == nil && written == len(p) {
		res.Observations.RequestPackets = 1
	}
	if e != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		return res, e
	}
	trace("RADIUS request sent; awaiting response")
	readStart := time.Now()
	r, e := ReadPacket(conn)
	mark("response read", readStart)
	if e != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		return res, e
	}
	// FreeRADIUS check_client_connections=yes can send a synthetic
	// Access-Accept with ID 0 before it sends the reply to this request.
	// Discard at most one such unrelated packet. It is never counted as a
	// successful login; only the matching reply is authenticated below.
	if r[0] == 2 && r[1] == 0 && p[1] != 0 {
		res.Observations.ConnectionChecks++
		readStart = time.Now()
		r, e = ReadPacket(conn)
		res.Observations.Phases["response read"] += time.Since(readStart)
		if e != nil {
			return res, e
		}
	}
	res.Observations.ResponseBytes = len(r)
	res.Observations.ResponsePackets = 1
	trace(fmt.Sprintf("RADIUS response received: code %d, ID %d, length %d bytes; attribute values hidden", r[0], r[1], len(r)))
	verifyStart := time.Now()
	e = verifyResponse(r, p, secret)
	mark("response verify", verifyStart)
	if e != nil {
		trace("RADIUS response validation failed: " + traceFailure(e))
		return res, e
	}
	trace("RADIUS response ID, code, authenticator and optional Message-Authenticator validated")
	res.Code = r[0]
	res.Name = map[byte]string{2: "Access-Accept", 3: "Access-Reject", 11: "Access-Challenge", 5: "Accounting-Response"}[r[0]]
	res.Duration = time.Since(start)
	for a := r[20:]; len(a) > 0; a = a[a[1]:] {
		res.Observations.ResponseAttributes++
		res.Attributes += fmt.Sprintf("Attribute %d (%d bytes; value hidden)\n", a[0], int(a[1])-2)
	}
	return res, nil
}

// traceFailure returns only fixed vocabulary; never expose OS, x509, or peer text.
func traceFailure(err error) string {
	var ca x509.UnknownAuthorityError
	var name x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &ca) {
		return "untrusted server CA"
	}
	if errors.As(err, &name) {
		return "server name mismatch"
	}
	if errors.As(err, &invalid) {
		return "server certificate invalid or expired"
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || os.IsTimeout(err) {
		return "timeout"
	}
	switch err.Error() {
	case "invalid response authenticator":
		return "response authenticator mismatch"
	case "invalid response Message-Authenticator":
		return "Message-Authenticator mismatch"
	}
	if strings.HasPrefix(err.Error(), "RADIUS identifier mismatch") {
		return "response ID mismatch"
	}
	if strings.HasPrefix(err.Error(), "unexpected RADIUS response code") {
		return "unexpected response code"
	}
	return "transport, certificate, or packet error (details hidden)"
}
