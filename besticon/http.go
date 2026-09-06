package besticon

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
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

// blockedPrefixes are the ranges the fetcher must never connect to: every
// range IANA's IPv4 and IPv6 Special-Purpose Address Registries mark as not
// globally reachable, plus a few that are routable in theory but only ever
// internal in practice.
//
// Ranges that legitimately carry a *public* IPv4 target -- the IPv6 transition
// formats -- are deliberately NOT listed here. Blocking those outright would
// break IPv6-only and 6to4 deployments, so they are decoded by
// embeddedIPv4 and their payload re-checked against this table instead.
var blockedPrefixes = []netip.Prefix{
	// IPv4
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network", RFC 1122
	netip.MustParsePrefix("10.0.0.0/8"),      // private, RFC 1918
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT, RFC 6598
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local; cloud metadata
	netip.MustParsePrefix("172.16.0.0/12"),   // private, RFC 1918
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast, deprecated
	netip.MustParsePrefix("192.168.0.0/16"),  // private, RFC 1918
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking, RFC 2544
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved; includes 255.255.255.255

	// IPv6
	netip.MustParsePrefix("::/128"),        // unspecified
	netip.MustParsePrefix("::1/128"),       // loopback
	netip.MustParsePrefix("::/96"),         // IPv4-compatible, deprecated
	netip.MustParsePrefix("100::/64"),      // discard-only, RFC 6666
	netip.MustParsePrefix("2001:2::/48"),   // benchmarking
	netip.MustParsePrefix("2001:20::/28"),  // ORCHIDv2
	netip.MustParsePrefix("2001:db8::/32"), // documentation
	netip.MustParsePrefix("5f00::/16"),     // SRv6 SIDs, RFC 9602
	netip.MustParsePrefix("fc00::/7"),      // unique local, RFC 4193
	netip.MustParsePrefix("fe80::/10"),     // link-local
	netip.MustParsePrefix("fec0::/10"),     // site-local, deprecated
	netip.MustParsePrefix("ff00::/8"),      // multicast
}

func isPrivateIP(ipAddr *net.IPAddr) bool {
	if ipAddr == nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(ipAddr.IP)
	if !ok {
		// Not 4 or 16 bytes. Nothing can be dialed from it, but do not
		// report it as public either -- fail closed.
		return true
	}
	return isBlockedAddr(addr.Unmap())
}

// isBlockedAddr reports whether addr is in a blocked range, or is an IPv6
// transition address whose embedded IPv4 is. The recursion terminates at depth
// one: embeddedIPv4 only ever returns IPv4 addresses, and returns nothing for
// an IPv4 input.
func isBlockedAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	for _, v4 := range embeddedIPv4(addr) {
		if isBlockedAddr(v4) {
			return true
		}
	}
	return false
}

var (
	prefix6to4     = netip.MustParsePrefix("2002::/16")
	prefixTeredo   = netip.MustParsePrefix("2001::/32")
	prefixNAT64WK  = netip.MustParsePrefix("64:ff9b::/96")
	prefixNAT64Loc = netip.MustParsePrefix("64:ff9b:1::/48")
	prefixV4Xlat   = netip.MustParsePrefix("::ffff:0:0:0/96")
)

// embeddedIPv4 returns every IPv4 address addr could be carrying as an IPv6
// transition address. It returns more than one candidate only for the RFC 8215
// local-use NAT64 prefix, where the embedding offset depends on a prefix length
// that is not recoverable from the address itself.
func embeddedIPv4(addr netip.Addr) []netip.Addr {
	if !addr.Is6() || addr.Is4In6() {
		return nil
	}
	b := addr.As16()

	v4 := func(a, b, c, d byte) netip.Addr { return netip.AddrFrom4([4]byte{a, b, c, d}) }

	switch {
	case prefix6to4.Contains(addr): // RFC 3056: 2002:V4ADDR::/48
		return []netip.Addr{v4(b[2], b[3], b[4], b[5])}

	case prefixTeredo.Contains(addr): // RFC 4380 s4: client IPv4 is the last
		// 32 bits, obfuscated by XOR with all ones. The server IPv4 at bytes
		// 4:8 is the relay, not the destination, so it is not checked.
		return []netip.Addr{v4(b[12]^0xff, b[13]^0xff, b[14]^0xff, b[15]^0xff)}

	case prefixNAT64WK.Contains(addr): // RFC 6052 s2.2, /96: v4 in the low 32 bits
		return []netip.Addr{v4(b[12], b[13], b[14], b[15])}

	case prefixNAT64Loc.Contains(addr): // RFC 8215 local-use NAT64.
		// RFC 6052 permits /32../96 embeddings and the address alone does not
		// say which was used, so every plausible offset is decoded and each is
		// checked. Byte 8 is the reserved "u" octet and is skipped. A decode
		// yielding 0.0.0.0 is the artifact of guessing the wrong length, not a
		// destination, so it is dropped rather than treated as unspecified.
		cands := []netip.Addr{
			v4(b[6], b[7], b[9], b[10]),    // /48
			v4(b[7], b[9], b[10], b[11]),   // /56
			v4(b[9], b[10], b[11], b[12]),  // /64
			v4(b[12], b[13], b[14], b[15]), // /96
		}
		out := cands[:0]
		for _, c := range cands {
			if c.As4()[0] != 0 {
				out = append(out, c)
			}
		}
		return out

	case prefixV4Xlat.Contains(addr): // RFC 2765 IPv4-translated, deprecated
		return []netip.Addr{v4(b[12], b[13], b[14], b[15])}
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
