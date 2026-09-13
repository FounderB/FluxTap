package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	if u != "" {
		if err := validateWebhookURLShape(u); err != nil {
			fmt.Fprintf(os.Stderr, "webhook disabled: %v\n", err)
			u = ""
		}
	}
	return &Webhook{
		url: u,
		client: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			if err := ValidateWebhookURL(req.URL.String()); err != nil {
				return err
			}
			return nil
		}},
		seen: map[string]time.Time{},
		dry:  cfg.DryRun,
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
		if err := validateWebhookURLShape(w.url); err != nil {
			return err
		}
		b, _ := json.Marshal(payload)
		fmt.Fprintf(os.Stderr, "[webhook dry-run] %s\n", string(b))
		return nil
	}
	dialAddr, err := PinWebhookDial(w.url)
	if err != nil {
		return err
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
	req.Header.Set("User-Agent", "FluxTap/0.3.2")

	u, _ := url.Parse(w.url)
	serverName := u.Hostname()
	client := pinnedClient(w.client, dialAddr, serverName)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook transport error")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook HTTP %d", resp.StatusCode)
	}
	return nil
}

func pinnedClient(base *http.Client, dialAddr, serverName string) *http.Client {
	timeout := 8 * time.Second
	var checkRedirect func(*http.Request, []*http.Request) error
	if base != nil {
		if base.Timeout > 0 {
			timeout = base.Timeout
		}
		checkRedirect = base.CheckRedirect
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddr)
		},
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: serverName,
		},
	}
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
		Transport:     transport,
	}
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
