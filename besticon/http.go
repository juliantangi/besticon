package besticon

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"syscall"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var _ http.RoundTripper = (*httpTransport)(nil)

type httpTransport struct {
	transport http.RoundTripper

	userAgent string
}

func (h *httpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", h.userAgent)
	return h.transport.RoundTrip(req)
}

func NewDefaultHTTPTransport(userAgent string) http.RoundTripper {
	return &httpTransport{
		transport: safeTransport,
		userAgent: userAgent,
	}
}

// safeTransport is the base http.Transport used for all outbound favicon
// fetches. Its Dialer.Control rejects connections to private/reserved
// addresses at dial time, for every connection attempt: the initial request,
// every redirect hop, and every candidate IP if a host resolves to multiple
// A/AAAA records. This is the actual security boundary against SSRF/DNS
// rebinding; checkPublicHost is only a fast-fail pre-flight check on top of
// it and must not be relied on alone.
//
// It is built by cloning http.DefaultTransport rather than by constructing a
// bare http.Transport, so that the stdlib's connection-pool and timeout
// defaults are preserved: a zero-valued Transport has no idle-connection
// limit and no IdleConnTimeout, which for a service that fetches from an
// unbounded set of hosts means idle connections accumulate and are never
// reaped. Cloning also keeps ForceAttemptHTTP2, without which a Transport
// carrying a custom DialContext silently drops to HTTP/1.1.
var safeTransport http.RoundTripper = newSafeTransport()

func newSafeTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()

	// Deliberately no proxy. With a proxy configured the dialer connects to
	// the proxy, so Control would validate the proxy's address and never see
	// the real target — the SSRF filter would pass everything.
	t.Proxy = nil

	t.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   controlBlockPrivateAddr,
	}).DialContext

	return t
}

func controlBlockPrivateAddr(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid address: %s", address)
	}
	if isPrivateIP(&net.IPAddr{IP: ip}) {
		return fmt.Errorf("connection to %s blocked: private/reserved address", ip)
	}
	return nil
}

func NewDefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Jar:       mustInitCookieJar(),
		Transport: NewDefaultHTTPTransport("Mozilla/5.0 (iPhone; CPU iPhone OS 10_0 like Mac OS X) AppleWebKit/602.1.38 (KHTML, like Gecko) Version/10.0 Mobile/14A5297c Safari/602.1"),
		// Re-validate the target of every redirect hop. Without this, the
		// initial-host check in Get only covers the first request: a public
		// host could 302 to a private/loopback/link-local address and the
		// default redirect-following client would happily follow it.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return checkPublicHost(req.URL.Hostname())
		},
	}
}

func (b *Besticon) Get(urlstring string) (*http.Response, error) {
	u, e := url.Parse(urlstring)
	if e != nil {
		return nil, e
	}
	// Maybe we can get rid of this conversion someday
	// https://github.com/golang/go/issues/13835
	u.Host, e = idna.ToASCII(u.Host)
	if e != nil {
		return nil, e
	}

	if e := checkPublicHost(u.Hostname()); e != nil {
		return nil, e
	}

	req, e := http.NewRequest("GET", u.String(), nil)
	if e != nil {
		return nil, e
	}

	start := time.Now()
	resp, err := b.httpClient.Do(req)
	end := time.Now()
	duration := end.Sub(start)

	b.logger.LogResponse(req, resp, duration, err)

	return resp, err
}

// checkPublicHost resolves host and rejects it if it maps to a
// loopback/private address. It is applied both to the initial URL and to the
// target of every redirect hop so that an allowed public host cannot be used
// to bounce a request onto an internal address.
func checkPublicHost(host string) error {
	ipAddr, e := net.ResolveIPAddr("ip", host)
	if e != nil {
		return e
	}
	if isPrivateIP(ipAddr) {
		return errors.New("private ip address disallowed")
	}
	return nil
}

func isPrivateIP(ipAddr *net.IPAddr) bool {
	if ipAddr == nil {
		return false
	}

	ip := ipAddr.IP
	// Unmap IPv4-in-IPv6 (e.g. ::ffff:100.64.0.1) to its 4-byte form. The
	// net.IP predicates below each call To4 internally, so this is not for
	// their benefit — it is what lets the hand-rolled CGNAT check further
	// down match on len(ip) == 4. Removing it silently stops that check
	// seeing IPv4-mapped addresses.
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || // 169.254.0.0/16, fe80::/10
		ip.IsMulticast() || // 224.0.0.0/4, ff00::/8
		ip.IsUnspecified() { // 0.0.0.0, ::
		return true
	}

	// CGNAT / shared address space, RFC 6598 (100.64.0.0/10)
	if len(ip) == 4 && ip[0] == 100 && ip[1]&0xc0 == 64 {
		return true
	}

	// IPv6 transition addresses that embed an IPv4 target
	// (6to4, NAT64, Teredo) — extract and re-check the embedded address.
	if embedded := extractEmbeddedIPv4(ipAddr.IP); embedded != nil {
		return isPrivateIP(&net.IPAddr{IP: embedded})
	}

	return false
}

// extractEmbeddedIPv4 pulls an IPv4 address out of known IPv6 transition
// address formats, or returns nil if ip isn't one of them.
func extractEmbeddedIPv4(ip net.IP) net.IP {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return nil // not IPv6, or already plain v4
	}

	switch {
	case ip16[0] == 0x20 && ip16[1] == 0x02: // 6to4: 2002:AABB:CCDD::/16
		return net.IPv4(ip16[2], ip16[3], ip16[4], ip16[5])
	case ip16[0] == 0x00 && ip16[1] == 0x64 && ip16[2] == 0xff && ip16[3] == 0x9b && // NAT64: 64:ff9b::/96
		ip16[4] == 0 && ip16[5] == 0 && ip16[6] == 0 && ip16[7] == 0 &&
		ip16[8] == 0 && ip16[9] == 0 && ip16[10] == 0 && ip16[11] == 0:
		return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
	case ip16[0] == 0x20 && ip16[1] == 0x01 && ip16[2] == 0x00 && ip16[3] == 0x00: // Teredo: 2001:0000::/32
		// client IPv4 sits in the last 4 bytes, XOR'd with 0xff — easy to get
		// wrong, don't "simplify" this without a test covering it.
		return net.IPv4(
			ip16[12]^0xff, ip16[13]^0xff, ip16[14]^0xff, ip16[15]^0xff,
		)
	}
	return nil
}

func (b *Besticon) GetBodyBytes(r *http.Response) ([]byte, error) {
	limitReader := io.LimitReader(r.Body, b.maxResponseBodySize)
	data, e := io.ReadAll(limitReader)
	r.Body.Close()

	if int64(len(data)) >= b.maxResponseBodySize {
		return nil, errors.New("body too large")
	}
	return data, e
}

func mustInitCookieJar() *cookiejar.Jar {
	options := cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}
	jar, e := cookiejar.New(&options)
	if e != nil {
		panic(e)
	}

	return jar
}
