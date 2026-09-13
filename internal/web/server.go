package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FounderB/FluxTap/internal/engine"
	"github.com/FounderB/FluxTap/internal/pcap"
	"github.com/gorilla/websocket"
)

type sub struct {
	c  *websocket.Conn
	mu sync.Mutex
}

type Server struct {
	eng     *engine.Engine
	addr    string
	token   string
	noAuth  bool
	mu      sync.RWMutex
	subs    map[*sub]bool
	up      websocket.Upgrader
}

// Options configures the dashboard HTTP/WS surface.
type Options struct {
	Addr   string
	Token  string // empty + NoAuth=false → auto-generate
	NoAuth bool
}

func New(eng *engine.Engine, opts Options) *Server {
	token := strings.TrimSpace(opts.Token)
	if !opts.NoAuth && token == "" {
		token = randomToken(16)
	}
	s := &Server{
		eng:    eng,
		addr:   opts.Addr,
		token:  token,
		noAuth: opts.NoAuth,
		subs:   map[*sub]bool{},
		up: websocket.Upgrader{
			CheckOrigin: checkOrigin,
		},
	}
	eng.SetHub(s)
	return s
}

func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // non-browser / same-origin navigations
	}
	host := r.Host
	allowed := []string{
		"http://" + host,
		"https://" + host,
		"http://127.0.0.1",
		"http://localhost",
		"https://127.0.0.1",
		"https://localhost",
	}
	for _, a := range allowed {
		if origin == a || strings.HasPrefix(origin, a+":") {
			return true
		}
	}
	// exact host match with scheme
	if strings.HasPrefix(origin, "http://"+host) || strings.HasPrefix(origin, "https://"+host) {
		return true
	}
	return false
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return hex.EncodeToString(b)
}

func (s *Server) Token() string { return s.token }
func (s *Server) AuthEnabled() bool {
	return !s.noAuth && s.token != ""
}

func (s *Server) Broadcast(event string, payload any) {
	msg, err := json.Marshal(map[string]any{"event": event, "data": payload})
	if err != nil {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for sub := range s.subs {
		sub.mu.Lock()
		_ = sub.c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		err := sub.c.WriteMessage(websocket.TextMessage, msg)
		sub.mu.Unlock()
		if err != nil {
			// drop on next read loop
			continue
		}
	}
}

func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/favicon.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(faviconPNG)
	})
	mux.HandleFunc("/api/stats", s.auth(s.handleStats))
	mux.HandleFunc("/api/packets", s.auth(s.handlePackets))
	mux.HandleFunc("/api/packet", s.auth(s.handlePacket))
	mux.HandleFunc("/api/flows", s.auth(s.handleFlows))
	mux.HandleFunc("/api/security", s.auth(s.handleSecurity))
	mux.HandleFunc("/api/status", s.auth(s.handleStatus))
	mux.HandleFunc("/api/ifaces", s.auth(s.handleIfaces))
	mux.HandleFunc("/api/control", s.auth(s.handleControl))
	mux.HandleFunc("/api/sessions", s.auth(s.handleSessions))
	mux.HandleFunc("/api/session", s.auth(s.handleSession))
	mux.HandleFunc("/api/story", s.auth(s.handleStory))
	mux.HandleFunc("/api/telegram/test", s.auth(s.handleTelegramTest))
	mux.HandleFunc("/api/webhook/test", s.auth(s.handleWebhookTest))
	mux.HandleFunc("/api/export.json", s.auth(s.handleExportJSON))
	mux.HandleFunc("/ws", s.handleWS)

	mode := "file"
	if s.eng.IsLive() {
		mode = "LIVE"
	}
	st := s.eng.Status()
	if src, _ := st["source"].(string); src != "" {
		mode = mode + "/" + src
	}
	url := "http://" + s.addr
	if s.AuthEnabled() {
		url = url + "/?token=" + s.token
	}
	fmt.Printf("⚡ FluxTap [%s] → %s\n", mode, url)
	if s.AuthEnabled() {
		fmt.Printf("🔐 dashboard token required (pass ?token= or Authorization: Bearer)\n")
	} else {
		fmt.Printf("⚠️  dashboard auth DISABLED (--no-auth)\n")
	}
	if host, _, err := net.SplitHostPort(s.addr); err == nil && host != "" && host != "127.0.0.1" && host != "localhost" && host != "::1" {
		fmt.Printf("⚠️  bind %s is not loopback — anyone who can reach it can use the API (token still required unless --no-auth)\n", s.addr)
	}
	// Timeouts harden the HTTP surface; Read/WriteTimeout left unset so
	// long-lived WebSocket sessions are not cut while idle between frames.
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           withSecurityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return srv.ListenAndServe()
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorize(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) authorize(r *http.Request) bool {
	if !s.AuthEnabled() {
		return true
	}
	tok := r.URL.Query().Get("token")
	if tok == "" {
		h := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(h), "bearer ") {
			tok = strings.TrimSpace(h[7:])
		}
	}
	if tok == "" {
		tok = r.Header.Get("X-FluxTap-Token")
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) == 1
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.eng.Stats.Snapshot())
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.eng.Flows.Top(100))
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.eng.Security.Findings())
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := s.eng.Status()
	st["auth"] = s.AuthEnabled()
	writeJSON(w, st)
}

func (s *Server) handleIfaces(w http.ResponseWriter, r *http.Request) {
	list, err := pcap.ListInterfaces()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, list)
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	var req struct {
		Action string `json:"action"`
	}
	_ = json.Unmarshal(body, &req)
	switch req.Action {
	case "pause":
		s.eng.Pause()
	case "resume":
		s.eng.Resume()
	case "stop":
		s.eng.Stop()
	default:
		http.Error(w, "unknown action", 400)
		return
	}
	writeJSON(w, s.eng.Status())
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	writeJSON(w, s.eng.Sessions.List(limit))
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "key required", 400)
		return
	}
	sess := s.eng.Sessions.Get(key)
	if sess == nil {
		http.Error(w, "not found", 404)
		return
	}
	writeJSON(w, sess)
}

func (s *Server) handleStory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.eng.Story())
}

func (s *Server) handleTelegramTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	if err := s.eng.Telegram.NotifyText("test ping from FluxTap dashboard"); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, s.eng.Telegram.Status())
}

func (s *Server) handleWebhookTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	if err := s.eng.Webhook.NotifyText("test ping from FluxTap dashboard"); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, s.eng.Webhook.Status())
}

func (s *Server) handlePackets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("filter")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	if limit > 300 {
		limit = 300
	}
	frames := s.eng.Filtered(q)
	if len(frames) > limit {
		frames = frames[len(frames)-limit:]
	}
	type row struct {
		No        uint64 `json:"no"`
		Timestamp any    `json:"timestamp"`
		Src       string `json:"src"`
		Dst       string `json:"dst"`
		Protocol  string `json:"protocol"`
		Length    int    `json:"length"`
		Info      string `json:"info"`
		Severity  string `json:"severity"`
		Tags      any    `json:"tags"`
		FlowKey   string `json:"flow_key"`
		Meta      any    `json:"meta"`
	}
	out := make([]row, 0, len(frames))
	for _, f := range frames {
		out = append(out, row{f.No, f.Timestamp, f.Src, f.Dst, f.Protocol, f.Length, f.Info, f.Severity, f.Tags, f.FlowKey, f.Meta})
	}
	writeJSON(w, out)
}

func (s *Server) handlePacket(w http.ResponseWriter, r *http.Request) {
	no, _ := strconv.ParseUint(r.URL.Query().Get("no"), 10, 64)
	f := s.eng.Frame(no)
	if f == nil {
		http.Error(w, "not found", 404)
		return
	}
	writeJSON(w, f)
}

func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=fluxtap.json")
	_ = s.eng.ExportJSON(w)
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	c, err := s.up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(64 << 10)
	sub := &sub{c: c}
	s.mu.Lock()
	s.subs[sub] = true
	s.mu.Unlock()

	writeWS := func(event string, data any) {
		sub.mu.Lock()
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = c.WriteJSON(map[string]any{"event": event, "data": data})
		sub.mu.Unlock()
	}
	writeWS("stats", s.eng.Stats.Snapshot())
	writeWS("status", s.eng.Status())
	writeWS("sessions", s.eng.Sessions.List(40))
	writeWS("story", s.eng.Story())

	go func() {
		for {
			_, data, err := c.ReadMessage()
			if err != nil {
				break
			}
			var msg struct {
				Cmd string `json:"cmd"`
			}
			if json.Unmarshal(data, &msg) == nil {
				switch msg.Cmd {
				case "pause":
					s.eng.Pause()
				case "resume":
					s.eng.Resume()
				case "stop":
					s.eng.Stop()
				}
			}
		}
		s.mu.Lock()
		delete(s.subs, sub)
		s.mu.Unlock()
		_ = c.Close()
	}()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Allow loading the shell without auth so the token can be pasted/stored from ?token=
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := indexHTML
	if s.AuthEnabled() {
		// inject bootstrap token hint (empty — client reads ?token=)
		html = strings.Replace(html, "/*__FLUXTAP_AUTH__*/", "window.__FLUXTAP_AUTH__=true;", 1)
	} else {
		html = strings.Replace(html, "/*__FLUXTAP_AUTH__*/", "window.__FLUXTAP_AUTH__=false;", 1)
	}
	_, _ = w.Write([]byte(html))
}
