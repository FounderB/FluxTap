package notify

import (
	"regexp"
	"strings"
)

var (
	tgBotTokenRE = regexp.MustCompile(`(?i)bot\d+:[A-Za-z0-9_-]{20,}`)
	bearerRE     = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._\-+=/]{8,}`)
)

// RedactSecrets strips bot tokens and bearer credentials from error/status text.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	s = tgBotTokenRE.ReplaceAllString(s, "bot***:***")
	s = bearerRE.ReplaceAllString(s, "${1}***")
	// also redact raw token if embedded without "bot" prefix in telegram URLs
	if i := strings.Index(s, "api.telegram.org/"); i >= 0 {
		rest := s[i:]
		if j := strings.Index(rest, "/"); j >= 0 {
			// keep host path shape without token segments
			s = s[:i] + "api.telegram.org/***"
		}
	}
	return s
}
