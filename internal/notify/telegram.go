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

// Telegram sends FluxTap security findings to a chat.
type Telegram struct {
	token  string
	chatID string
	client *http.Client
	mu     sync.Mutex
	seen   map[string]time.Time
	sent   int
	last   string
	dry    bool
}

type Config struct {
	Token  string
	ChatID string
	DryRun bool
}

func NewTelegram(cfg Config) *Telegram {
	tok := cfg.Token
	if tok == "" {
		tok = os.Getenv("FLUXTAP_TG_TOKEN")
	}
	chat := cfg.ChatID
	if chat == "" {
		chat = os.Getenv("FLUXTAP_TG_CHAT")
	}
	return &Telegram{
		token:  strings.TrimSpace(tok),
		chatID: strings.TrimSpace(chat),
		client: &http.Client{Timeout: 8 * time.Second},
		seen:   map[string]time.Time{},
		dry:    cfg.DryRun,
	}
}

func (t *Telegram) Enabled() bool {
	return t != nil && t.token != "" && t.chatID != ""
}

func (t *Telegram) Status() map[string]any {
	if t == nil {
		return map[string]any{"enabled": false}
	}
	return map[string]any{
		"enabled": t.Enabled(),
		"chat":    mask(t.chatID),
		"sent":    t.sent,
		"last":    t.last,
		"dry_run": t.dry,
	}
}

func (t *Telegram) NotifyFinding(f security.Finding) {
	if !t.Enabled() {
		return
	}
	// de-dupe same rule+src within 60s
	key := f.Rule + "|" + f.Src + "|" + f.Dst
	t.mu.Lock()
	if ts, ok := t.seen[key]; ok && time.Since(ts) < 60*time.Second {
		t.mu.Unlock()
		return
	}
	t.seen[key] = time.Now()
	t.mu.Unlock()

	icon := "⚠️"
	if f.Severity == "alert" {
		icon = "🚨"
	}
	text := fmt.Sprintf(
		"%s *FluxTap*%s\n*%s* · `%s`\n%s\n`%s` → `%s`\nframe #%d",
		icon, tern(t.dry, " _(dry-run)_", ""),
		escapeMD(f.Severity), escapeMD(f.Rule),
		escapeMD(f.Message),
		escapeMD(f.Src), escapeMD(f.Dst), f.FrameNo,
	)
	if err := t.send(text); err != nil {
		t.mu.Lock()
		t.last = "err: " + err.Error()
		t.mu.Unlock()
		return
	}
	t.mu.Lock()
	t.sent++
	t.last = f.Rule + " @ " + time.Now().Format(time.RFC3339)
	t.mu.Unlock()
}

func (t *Telegram) NotifyText(msg string) error {
	if !t.Enabled() {
		return fmt.Errorf("telegram not configured")
	}
	return t.send("⚡ *FluxTap*\n" + escapeMD(msg))
}

func (t *Telegram) send(text string) error {
	if t.dry {
		fmt.Fprintf(os.Stderr, "[telegram dry-run] %s\n", text)
		return nil
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.token)
	body, _ := json.Marshal(map[string]any{
		"chat_id":    t.chatID,
		"text":       text,
		"parse_mode": "Markdown",
		"disable_web_page_preview": true,
	})
	resp, err := t.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return fmt.Errorf("telegram HTTP %d: %s", resp.StatusCode, buf.String())
	}
	return nil
}

func escapeMD(s string) string {
	r := strings.NewReplacer("_", "\\_", "*", "\\*", "`", "\\`", "[", "\\[")
	return r.Replace(s)
}

func mask(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "…" + s[len(s)-2:]
}

func tern(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}
