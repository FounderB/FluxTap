package notify_test

import (
	"strings"
	"testing"

	"github.com/FounderB/FluxTap/internal/notify"
)

func TestRedactSecrets(t *testing.T) {
	in := "https://api.telegram.org/bot123456789:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/sendMessage boom"
	out := notify.RedactSecrets(in)
	if strings.Contains(out, "AAH") || strings.Contains(out, "bot123456789:") {
		t.Fatalf("token leaked: %q", out)
	}
	if !strings.Contains(notify.RedactSecrets("Bearer SUPERSECRETOKEN123"), "***") {
		t.Fatal("bearer not redacted")
	}
}

func TestWebhookDry(t *testing.T) {
	w := notify.NewWebhook(notify.WebhookConfig{URL: "https://example.test/hook", DryRun: true})
	if !w.Enabled() {
		t.Fatal("expected enabled")
	}
	if err := w.NotifyText("ping"); err != nil {
		t.Fatal(err)
	}
	st := w.Status()
	if st["dry_run"] != true {
		t.Fatalf("status: %#v", st)
	}
}
