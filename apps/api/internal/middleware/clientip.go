package middleware

import (
	"fmt"
	"net"
	"strings"

	"github.com/labstack/echo/v4"
)

// ClientIPExtractor builds the echo.IPExtractor that c.RealIP() uses, from the
// SBOMHUB_TRUSTED_PROXIES setting (a comma/space separated list of IP
// addresses and CIDRs).
//
// Why this exists: echo v4.16.3 (GHSA-246p-cpwv-v3jq / GHSA-99jh-6h7p-pp36)
// stopped trusting X-Forwarded-For / X-Real-IP when Echo#IPExtractor is unset.
// Before that, any client could pick its own c.RealIP() — and with it its own
// per-IP rate-limit bucket and the IP recorded in audit logs. The new default
// is the connection peer, which is correct for a directly exposed server but
// collapses every client behind a reverse proxy into the proxy's address.
//
//   - Empty spec: echo.ExtractIPDirect() — the connection peer, forwarding
//     headers ignored. Same as echo's own default; stated explicitly so the
//     choice is visible at the wiring site.
//   - Non-empty spec: X-Forwarded-For is honoured only for hops that come from
//     the listed ranges. echo's broad implicit trust (loopback, link-local,
//     every RFC1918 network) is switched OFF, so only what the operator names
//     is trusted — a co-tenant on the same private network cannot spoof
//     unless its address falls inside a range the operator listed, so exact
//     proxy addresses are preferred over CIDRs.
//
// An unparseable entry, or a non-blank value that names no proxy at all (","),
// is an error so a typo is a startup refusal rather than a silently untrusted
// proxy. Only a blank value selects the direct mode.
func ClientIPExtractor(spec string) (echo.IPExtractor, error) {
	fields := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	if len(fields) == 0 {
		if strings.TrimSpace(spec) != "" {
			// Non-blank but names no proxy (e.g. ","): a typo, not an
			// opt-out. Refuse rather than silently running in direct mode
			// while the operator believes proxies are trusted.
			return nil, fmt.Errorf("SBOMHUB_TRUSTED_PROXIES: %q names no proxy address (leave it empty to trust none)", spec)
		}
		return echo.ExtractIPDirect(), nil
	}

	opts := []echo.TrustOption{
		echo.TrustLoopback(false),
		echo.TrustLinkLocal(false),
		echo.TrustPrivateNet(false),
	}
	for _, f := range fields {
		ipNet, err := parseTrustedProxy(f)
		if err != nil {
			return nil, err
		}
		opts = append(opts, echo.TrustIPRange(ipNet))
	}
	return echo.ExtractIPFromXFFHeader(opts...), nil
}

func parseTrustedProxy(s string) (*net.IPNet, error) {
	if strings.Contains(s, "/") {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("SBOMHUB_TRUSTED_PROXIES: invalid CIDR %q: %w", s, err)
		}
		return ipNet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("SBOMHUB_TRUSTED_PROXIES: invalid IP address %q", s)
	}
	bits := 128
	if v4 := ip.To4(); v4 != nil {
		ip, bits = v4, 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}
