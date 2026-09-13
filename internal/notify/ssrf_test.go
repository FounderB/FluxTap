package notify

import "testing"

func TestValidateWebhookURL(t *testing.T) {
	ok := []string{
		"https://hooks.slack.com/services/T00/B00/XXX",
		"https://example.com/hook",
	}
	for _, u := range ok {
		if err := ValidateWebhookURL(u); err != nil {
			t.Fatalf("%s: %v", u, err)
		}
	}
	bad := []string{
		"",
		"ftp://example.com/x",
		"http://example.com/x",
		"https://127.0.0.1/hook",
		"https://10.0.0.1/hook",
		"https://100.64.1.1/hook",
		"https://169.254.169.254/latest",
		"https://metadata.google.internal/",
		"not-a-url",
	}
	for _, u := range bad {
		if err := ValidateWebhookURL(u); err == nil {
			t.Fatalf("expected reject for %q", u)
		}
	}
	// localhost http allowed for lab dry-runs
	if err := ValidateWebhookURL("http://127.0.0.1:9/hook"); err != nil {
		t.Fatalf("localhost http: %v", err)
	}
}
