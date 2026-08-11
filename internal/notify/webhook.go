package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/FounderB/FluxTap/internal/security"
)

// Webhook POSTs JSON findings to an operator URL (Slack-compatible or generic).
type Webhook struct {
	url    string
	client *http.Client
	mu     sync.Mutex
	seen   map[string]time.Time
	sent   int
	last   string
	dry    bool
}

type WebhookConfig struct {
	URL    string
	DryRun bool
}

func NewWebhook(cfg WebhookConfig) *Webhook {
	u := strings.TrimSpace(cfg.URL)
	if u == "" {
		u = strings.TrimSpace(os.Getenv("FLUXTAP_WEBHOOK_URL"))
	}
	return &Webhook{
		url:    u,
		client: &http.Client{Timeout: 8 * time.Second},
		seen:   map[string]time.Time{},
		dry:    cfg.DryRun,
	}
}

func (w *Webhook) Enabled() bool {
	return w != nil && w.url != ""
}

func (w *Webhook) Status() map[string]any {
	if w == nil {
		return map[string]any{"enabled": false}
	}
	return map[string]any{
		"enabled": w.Enabled(),
		"url":     maskURL(w.url),
		"sent":    w.sent,
		"last":    RedactSecrets(w.last),
		"dry_run": w.dry,
	}
}

func (w *Webhook) NotifyFinding(f security.Finding) {
	if !w.Enabled() {
		return
	}
	key := f.Rule + "|" + f.Src + "|" + f.Dst
	w.mu.Lock()
	if ts, ok := w.seen[key]; ok && time.Since(ts) < 60*time.Second {
		w.mu.Unlock()
		return
	}
	w.seen[key] = time.Now()
	if len(w.seen) > 2000 {
		w.seen = map[string]time.Time{key: time.Now()}
	}
	w.mu.Unlock()

	payload := map[string]any{
		"source":    "fluxtap",
		"severity": f.Severity,
		"rule":      f.Rule,
		"message":   f.Message,
		"src":       f.Src,
		"dst":       f.Dst,
		"frame_no":  f.FrameNo,
		"time":      f.Time.Format(time.RFC3339Nano),
		"text": fmt.Sprintf("[FluxTap] %s %s: %s (%s → %s) frame #%d",
			f.Severity, f.Rule, f.Message, f.Src, f.Dst, f.FrameNo),
	}
	if err := w.post(payload); err != nil {
		w.mu.Lock()
		w.last = "err: " + RedactSecrets(err.Error())
		w.mu.Unlock()
		return
	}
	w.mu.Lock()
	w.sent++
	w.last = f.Rule + " @ " + time.Now().Format(time.RFC3339)
	w.mu.Unlock()
}

func (w *Webhook) NotifyText(msg string) error {
	if !w.Enabled() {
		return fmt.Errorf("webhook not configured")
	}
	return w.post(map[string]any{
		"source": "fluxtap",
		"text":   msg,
	})
}

func (w *Webhook) post(payload map[string]any) error {
	if w.dry {
		b, _ := json.Marshal(payload)
		fmt.Fprintf(os.Stderr, "[webhook dry-run] %s\n", string(b))
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "FluxTap/0.3")
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook transport error")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook HTTP %d", resp.StatusCode)
	}
	return nil
}

func maskURL(u string) string {
	if u == "" {
		return ""
	}
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			return u[:i+3] + rest[:slash] + "/***"
		}
		return u[:i+3] + "***"
	}
	return "***"
}
