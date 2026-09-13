package notify

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateWebhookURL rejects non-HTTPS (except localhost HTTP for dry labs) and
// private / link-local / metadata destinations to reduce SSRF risk.
func ValidateWebhookURL(raw string) error {
	_, err := PinWebhookDial(raw)
	return err
}

// PinWebhookDial validates the URL then returns a dial address (ip:port) pinned
// to a resolved, allowed IP so a later DNS rebind cannot redirect the POST.
func PinWebhookDial(raw string) (dialAddr string, err error) {
	if err := validateWebhookURLShape(raw); err != nil {
		return "", err
	}
	u, _ := url.Parse(strings.TrimSpace(raw))
	host := strings.ToLower(u.Hostname())
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	var pick net.IP
	if ip := net.ParseIP(host); ip != nil {
		if !(isLocalHostname(host) && scheme == "http") && isBlockedIP(ip) {
			return "", fmt.Errorf("webhook URL resolves to a blocked address")
		}
		pick = ip
	} else if isLocalHostname(host) && scheme == "http" {
		pick = net.ParseIP("127.0.0.1")
		if host == "::1" {
			pick = net.ParseIP("::1")
		}
	} else {
		addrs, err := net.LookupIP(host)
		if err != nil {
			return "", fmt.Errorf("webhook URL host lookup failed")
		}
		if len(addrs) == 0 {
			return "", fmt.Errorf("webhook URL host has no addresses")
		}
		for _, ip := range addrs {
			if isBlockedIP(ip) {
				return "", fmt.Errorf("webhook URL resolves to a blocked address")
			}
		}
		pick = addrs[0]
	}
	return net.JoinHostPort(pick.String(), port), nil
}

func validateWebhookURLShape(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("empty webhook URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid webhook URL")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("webhook URL missing host")
	}
	switch scheme {
	case "https":
		// ok
	case "http":
		if !isLocalHostname(host) {
			return fmt.Errorf("webhook URL must use https (http only allowed for localhost)")
		}
	default:
		return fmt.Errorf("webhook URL scheme must be https")
	}
	if looksBlockedHostname(host) {
		return fmt.Errorf("webhook URL host is not allowed")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isLocalHostname(host) && scheme == "http" {
			return nil
		}
		if isBlockedIP(ip) {
			return fmt.Errorf("webhook URL resolves to a blocked address")
		}
	}
	return nil
}

func isLocalHostname(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func looksBlockedHostname(host string) bool {
	if host == "metadata.google.internal" || strings.HasSuffix(host, ".internal") {
		return true
	}
	if strings.HasSuffix(host, ".local") && host != "localhost" {
		return true
	}
	return false
}

func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// CGNAT / shared address space (RFC 6598): 100.64.0.0/10
		// net.IP.IsPrivate does not cover this range.
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}
	return false
}
