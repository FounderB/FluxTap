package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/FounderB/FluxTap/internal/engine"
	"github.com/FounderB/FluxTap/internal/pcap"
)

type Server struct {
	eng  *engine.Engine
	addr string
	mu   sync.RWMutex
	subs map[*websocket.Conn]bool
	up   websocket.Upgrader
}

func New(eng *engine.Engine, addr string) *Server {
	s := &Server{
		eng:  eng,
		addr: addr,
		subs: map[*websocket.Conn]bool{},
		up: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
	eng.SetHub(s)
	return s
}

func (s *Server) Broadcast(event string, payload any) {
	msg, err := json.Marshal(map[string]any{"event": event, "data": payload})
	if err != nil {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for c := range s.subs {
		_ = c.WriteMessage(websocket.TextMessage, msg)
	}
}

func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/packets", s.handlePackets)
	mux.HandleFunc("/api/packet", s.handlePacket)
	mux.HandleFunc("/api/flows", s.handleFlows)
	mux.HandleFunc("/api/security", s.handleSecurity)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/ifaces", s.handleIfaces)
	mux.HandleFunc("/api/control", s.handleControl)
	mux.HandleFunc("/api/sessions", s.handleSessions)
	mux.HandleFunc("/api/session", s.handleSession)
	mux.HandleFunc("/api/telegram/test", s.handleTelegramTest)
	mux.HandleFunc("/api/export.json", s.handleExportJSON)
	mux.HandleFunc("/ws", s.handleWS)
	mode := "file"
	if s.eng.IsLive() {
		mode = "LIVE"
	}
	st := s.eng.Status()
	if src, _ := st["source"].(string); src != "" {
		mode = mode + "/" + src
	}
	fmt.Printf("⚡ FluxTap [%s] → http://%s\n", mode, s.addr)
	return http.ListenAndServe(s.addr, mux)
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
	writeJSON(w, s.eng.Status())
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
	c, err := s.up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.subs[c] = true
	s.mu.Unlock()
	_ = c.WriteJSON(map[string]any{"event": "stats", "data": s.eng.Stats.Snapshot()})
	_ = c.WriteJSON(map[string]any{"event": "status", "data": s.eng.Status()})
	_ = c.WriteJSON(map[string]any{"event": "sessions", "data": s.eng.Sessions.List(40)})
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
		delete(s.subs, c)
		s.mu.Unlock()
		c.Close()
	}()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}
