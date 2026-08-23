package besticon

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		// Loopback
		{"loopback v4", "127.0.0.1", true},
		{"loopback v6", "::1", true},

		// RFC1918 private
		{"rfc1918 10.x", "10.0.0.1", true},
		{"rfc1918 172.16.x", "172.16.0.1", true},
		{"rfc1918 192.168.x", "192.168.0.1", true},

		// RFC4193 unique local IPv6
		{"rfc4193", "fc00::1", true},

		// Link-local unicast
		{"link-local v4 metadata", "169.254.169.254", true},
		{"link-local v4", "169.254.1.1", true},
		{"link-local v6", "fe80::1", true},

		// Multicast
		{"multicast v4 link-local", "224.0.0.1", true},
		{"multicast v4 global scope", "239.1.2.3", true},
		{"link-local multicast v6", "ff02::1", true},
		{"multicast v6 global scope", "ff0e::1", true},

		// Unspecified
		{"unspecified v4", "0.0.0.0", true},
		{"unspecified v6", "::", true},

		// CGNAT / RFC 6598 (100.64.0.0/10)
		{"cgnat start", "100.64.0.1", true},
		{"cgnat end", "100.127.255.255", true},
		{"cgnat just below range", "100.63.255.255", false},
		{"cgnat just above range", "100.128.0.0", false},

		// IPv4-mapped IPv6
		{"ipv4-mapped metadata", "::ffff:169.254.169.254", true},
		{"ipv4-mapped cgnat", "::ffff:100.64.0.1", true},

		// IPv6 transition addresses embedding a private IPv4
		{"6to4 metadata", "2002:a9fe:a9fe::", true},
		{"nat64 metadata", "64:ff9b::a9fe:a9fe", true},
		{"teredo metadata", "2001::5601:5601", true},

		// Public IPs must not be flagged
		{"public v4 google dns", "8.8.8.8", false},
		{"public v4 cloudflare dns", "1.1.1.1", false},
		{"public v6", "2606:4700:4700::1111", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse test IP %q", tt.ip)
			}
			got := isPrivateIP(&net.IPAddr{IP: ip})
			if got != tt.want {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsPrivateIPNil(t *testing.T) {
	if isPrivateIP(nil) {
		t.Error("isPrivateIP(nil) should be false")
	}
}

func TestExtractEmbeddedIPv4(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string // "" means nil expected
	}{
		{"6to4", "2002:a9fe:a9fe::", "169.254.169.254"},
		{"nat64", "64:ff9b::a9fe:a9fe", "169.254.169.254"},
		{"teredo", "2001::5601:5601", "169.254.169.254"},
		{"non-transition ipv6", "2606:4700:4700::1111", ""},
		{"plain ipv4", "8.8.8.8", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse test IP %q", tt.ip)
			}
			got := extractEmbeddedIPv4(ip)
			if tt.want == "" {
				if got != nil {
					t.Errorf("extractEmbeddedIPv4(%s) = %v, want nil", tt.ip, got)
				}
				return
			}
			want := net.ParseIP(tt.want)
			if got == nil || !got.Equal(want) {
				t.Errorf("extractEmbeddedIPv4(%s) = %v, want %v", tt.ip, got, want)
			}
		})
	}
}

// TestControlBlockPrivateAddr verifies the dial-time Control callback used by
// safeTransport directly, since it is invoked by net.Dialer with a raw
// "host:port" string rather than through isPrivateIP's net.IPAddr signature.
func TestControlBlockPrivateAddr(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{"metadata endpoint", "169.254.169.254:80", true},
		{"loopback", "127.0.0.1:8080", true},
		{"cgnat", "100.100.100.200:80", true},
		{"public ip", "8.8.8.8:443", false},
		{"no port at all", "not-an-address", true},
		{"host:port but not an IP literal", "metadata.internal:80", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := controlBlockPrivateAddr("tcp", tt.address, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("controlBlockPrivateAddr(%q) err = %v, wantErr %v", tt.address, err, tt.wantErr)
			}
		})
	}
}

// TestDialTimeEnforcementEndToEnd drives a real request through the
// transport built by NewDefaultHTTPTransport (the one wired into
// Besticon.Get's http.Client) to confirm a private target is rejected at
// dial time, not just at the isPrivateIP unit level. It calls the
// transport's RoundTrip directly rather than going through Besticon.Get, so
// that a plain loopback listener suffices: Get's own pre-flight
// checkPublicHost check would otherwise reject a loopback target before the
// dialer ever ran, which would prove nothing about the dial-time Control
// callback specifically.
func TestDialTimeEnforcementEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen on loopback: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("SHOULD NOT BE REACHABLE"))
	})}
	go srv.Serve(ln)
	defer srv.Close()

	client := &http.Client{Transport: NewDefaultHTTPTransport("test-agent")}
	req, err := http.NewRequest("GET", "http://"+ln.Addr().String()+"/favicon", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}

	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected dial-time rejection of loopback address, got nil error")
	}
	if !strings.Contains(err.Error(), "blocked: private/reserved address") {
		t.Fatalf("expected dial-time block error, got: %v", err)
	}
}

// TestGetFollowsRedirectToPrivateHost verifies that a public host which
// redirects to a loopback/private address cannot be used to reach an internal
// service. The initial-host check alone is not enough: the redirect target
// must be re-validated too.
func TestGetFollowsRedirectToPrivateHost(t *testing.T) {
	var internalHit int32

	// "Internal" service on loopback. A direct request to it is rejected by
	// the initial-host check; reaching it requires the redirect bypass.
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&internalHit, 1)
		w.Write([]byte("INTERNAL"))
	}))
	defer internal.Close()

	// Public decoy: bound to the host link-local address (non-loopback,
	// non-private per net.IP), so the initial-host check allows it. It
	// redirects to the loopback internal service.
	llHost := linkLocalHost(t)
	ln, err := net.Listen("tcp", llHost+":0")
	if err != nil {
		t.Skipf("cannot bind link-local %s: %v", llHost, err)
	}
	decoy := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/secret", http.StatusFound)
	})}
	go decoy.Serve(ln)
	defer decoy.Close()

	b := New()
	resp, err := b.Get("http://" + ln.Addr().String() + "/favicon")
	if resp != nil {
		resp.Body.Close()
	}

	if atomic.LoadInt32(&internalHit) != 0 {
		t.Fatalf("redirect bypass: internal loopback service was reached via 302 (hits=%d)", internalHit)
	}
	if err == nil {
		t.Fatalf("expected redirect to private host to be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "private ip address disallowed") {
		t.Fatalf("expected 'private ip address disallowed', got: %v", err)
	}
}

// TestGetRejectsDirectPrivateHost is the negative control: a direct request to
// a loopback address is already rejected by the initial-host check.
func TestGetRejectsDirectPrivateHost(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("INTERNAL"))
	}))
	defer internal.Close()

	b := New()
	resp, err := b.Get(internal.URL + "/secret")
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "private ip address disallowed") {
		t.Fatalf("expected direct loopback request to be rejected, got err=%v", err)
	}
}

// linkLocalHost returns a usable non-loopback, non-private IP (link-local) on
// the host so the decoy server passes the initial-host check.
func linkLocalHost(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.To4() == nil {
			continue
		}
		if ip.IsLinkLocalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() {
			return ip.String()
		}
	}
	t.Skip("no usable link-local IPv4 address on host")
	return ""
}

// TestSafeTransportKeepsStdlibDefaults guards against safeTransport being
// rebuilt as a bare &http.Transport{}, which would silently drop the
// connection-pool bounds, the TLS handshake timeout and HTTP/2.
func TestSafeTransportKeepsStdlibDefaults(t *testing.T) {
	def := http.DefaultTransport.(*http.Transport)
	got, ok := safeTransport.(*http.Transport)
	if !ok {
		t.Fatalf("safeTransport is %T, want *http.Transport", safeTransport)
	}

	if got.Proxy != nil {
		t.Error("safeTransport must not use a proxy: Control would validate the proxy address, not the target")
	}
	if !got.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 must stay set, or a custom DialContext drops the transport to HTTP/1.1")
	}
	if got.MaxIdleConns != def.MaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d (0 means unbounded)", got.MaxIdleConns, def.MaxIdleConns)
	}
	if got.IdleConnTimeout != def.IdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v (0 means idle conns are never reaped)", got.IdleConnTimeout, def.IdleConnTimeout)
	}
	if got.TLSHandshakeTimeout != def.TLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", got.TLSHandshakeTimeout, def.TLSHandshakeTimeout)
	}
	if got.ExpectContinueTimeout != def.ExpectContinueTimeout {
		t.Errorf("ExpectContinueTimeout = %v, want %v", got.ExpectContinueTimeout, def.ExpectContinueTimeout)
	}
}
