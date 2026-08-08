package engine

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FounderB/FluxTap/internal/decode"
	"github.com/FounderB/FluxTap/internal/filter"
	"github.com/FounderB/FluxTap/internal/flow"
	"github.com/FounderB/FluxTap/internal/notify"
	"github.com/FounderB/FluxTap/internal/pcap"
	"github.com/FounderB/FluxTap/internal/security"
	"github.com/FounderB/FluxTap/internal/session"
	"github.com/FounderB/FluxTap/internal/stats"
)

type Config struct {
	Path         string
	Iface        string
	BPF          string
	Filter       string
	MaxPackets   int
	IncludeHex   bool
	Speed        time.Duration
	Promisc      bool
	Stdin        bool
	Kernel       bool // AF_PACKET TPACKET_V3 ring
	TelegramTok  string
	TelegramChat string
	TelegramDry  bool
}

type Hub interface {
	Broadcast(event string, payload any)
}

type Engine struct {
	cfg       Config
	dissector *decode.Dissector
	Stats     *stats.Engine
	Flows     *flow.Tracker
	Security  *security.Analyzer
	Sessions  *session.Player
	Telegram  *notify.Telegram
	mu        sync.RWMutex
	frames    []*decode.Frame
	maxStore  int
	hub       Hub
	running   atomic.Bool
	paused    atomic.Bool
	live      bool
	source    string // file|tcpdump|kernel|stdin
	stopCh    chan struct{}
	pktNo     atomic.Uint64
}

func New(cfg Config) *Engine {
	d := decode.NewDissector()
	d.IncludeHex = cfg.IncludeHex
	return &Engine{
		cfg:       cfg,
		dissector: d,
		Stats:     stats.New(),
		Flows:     flow.NewTracker(10000),
		Security:  security.New(),
		Sessions:  session.NewPlayer(3000),
		Telegram:  notify.NewTelegram(notify.Config{Token: cfg.TelegramTok, ChatID: cfg.TelegramChat, DryRun: cfg.TelegramDry}),
		frames:    make([]*decode.Frame, 0, 4096),
		maxStore:  50000,
		stopCh:    make(chan struct{}),
		live:      cfg.Iface != "" || cfg.Stdin,
	}
}

func (e *Engine) SetHub(h Hub) { e.hub = h }
func (e *Engine) IsLive() bool  { return e.live }
func (e *Engine) IsPaused() bool {
	return e.paused.Load()
}
func (e *Engine) IsRunning() bool {
	return e.running.Load()
}

func (e *Engine) Pause() {
	e.paused.Store(true)
	if e.hub != nil {
		e.hub.Broadcast("status", e.Status())
	}
}

func (e *Engine) Resume() {
	e.paused.Store(false)
	if e.hub != nil {
		e.hub.Broadcast("status", e.Status())
	}
}

func (e *Engine) Status() map[string]any {
	return map[string]any{
		"live":     e.live,
		"running":  e.running.Load(),
		"paused":   e.paused.Load(),
		"iface":    e.cfg.Iface,
		"path":     e.cfg.Path,
		"packets":  e.pktNo.Load(),
		"source":   e.source,
		"sessions": e.Sessions.Count(),
		"telegram": e.Telegram.Status(),
	}
}

func (e *Engine) Frames() []*decode.Frame {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*decode.Frame, len(e.frames))
	copy(out, e.frames)
	return out
}

func (e *Engine) Frame(no uint64) *decode.Frame {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, f := range e.frames {
		if f.No == no {
			return f
		}
	}
	return nil
}

func (e *Engine) Filtered(expr string) []*decode.Frame {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []*decode.Frame
	for _, f := range e.frames {
		if filter.Match(f, expr) {
			out = append(out, f)
		}
	}
	return out
}

func (e *Engine) Stop() {
	select {
	case <-e.stopCh:
	default:
		close(e.stopCh)
	}
}

type packetSource interface {
	Next() (*pcap.Packet, error)
	Close() error
}

type fileSource struct{ *pcap.Reader }

func (f fileSource) Close() error { return f.Reader.Close() }

func (e *Engine) openSource() (packetSource, error) {
	if e.cfg.Stdin {
		e.source = "stdin"
		live, err := pcap.OpenLive(pcap.LiveOpts{Stdin: true})
		return live, err
	}
	if e.cfg.Iface != "" {
		if e.cfg.Kernel && e.cfg.Iface != "any" {
			kt, err := pcap.OpenKernel(pcap.KernelOpts{
				Iface: e.cfg.Iface, SnapLen: 65535, Promisc: e.cfg.Promisc,
			})
			if err == nil {
				e.source = "kernel"
				e.cfg.Iface = kt.Iface()
				return kt, nil
			}
			// fall back to tcpdump with warning
			fmt.Fprintf(os.Stderr, "kernel tap unavailable (%v) — falling back to tcpdump\n", err)
		}
		e.source = "tcpdump"
		return pcap.OpenLive(pcap.LiveOpts{
			Iface: e.cfg.Iface, SnapLen: 65535, BPF: e.cfg.BPF, Promisc: e.cfg.Promisc,
		})
	}
	e.source = "file"
	rd, err := pcap.Open(e.cfg.Path)
	if err != nil {
		return nil, err
	}
	return fileSource{rd}, nil
}

func (e *Engine) Run() error {
	src, err := e.openSource()
	if err != nil {
		return err
	}
	defer src.Close()
	if e.cfg.Iface != "" || e.cfg.Stdin {
		e.live = true
	}

	e.running.Store(true)
	defer e.running.Store(false)

	start := time.Now()
	var matched int
	lastStats := time.Now()

	if e.hub != nil {
		e.hub.Broadcast("status", e.Status())
	}
	if e.Telegram.Enabled() {
		_ = e.Telegram.NotifyText(fmt.Sprintf("online · source=%s iface=%s", e.source, e.cfg.Iface))
	}

	for {
		select {
		case <-e.stopCh:
			goto done
		default:
		}

		for e.paused.Load() {
			select {
			case <-e.stopCh:
				goto done
			case <-time.After(50 * time.Millisecond):
			}
		}

		pkt, err := src.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		e.ingest(pkt)
		matched++

		if e.hub != nil && time.Since(lastStats) > 500*time.Millisecond {
			e.hub.Broadcast("stats", e.Stats.Snapshot())
			e.hub.Broadcast("security", e.Security.Findings())
			e.hub.Broadcast("sessions", e.Sessions.List(40))
			lastStats = time.Now()
		}
		if e.cfg.Speed > 0 {
			time.Sleep(e.cfg.Speed)
		}
		if e.cfg.MaxPackets > 0 && matched >= e.cfg.MaxPackets {
			break
		}
	}

done:
	elapsed := time.Since(start)
	if e.hub != nil {
		e.hub.Broadcast("stats", e.Stats.Snapshot())
		e.hub.Broadcast("flows", e.Flows.Top(50))
		e.hub.Broadcast("security", e.Security.Findings())
		e.hub.Broadcast("sessions", e.Sessions.List(40))
		e.hub.Broadcast("status", e.Status())
		if !e.live {
			pps := 0.0
			if elapsed.Seconds() > 0 {
				pps = float64(matched) / elapsed.Seconds()
			}
			e.hub.Broadcast("done", map[string]any{
				"packets": matched,
				"ms":      elapsed.Milliseconds(),
				"pps":     pps,
			})
		}
	}
	return nil
}

func (e *Engine) ingest(pkt *pcap.Packet) {
	no := e.pktNo.Add(1)
	ts := pkt.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	fr := e.dissector.Dissect(no, ts, pkt.CapLen, pkt.OrigLen, pkt.LinkType, pkt.Data)
	raised := e.Security.Observe(fr)
	for _, finding := range raised {
		e.Telegram.NotifyFinding(finding)
		if e.hub != nil {
			e.hub.Broadcast("alert", finding)
		}
	}
	if !filter.Match(fr, e.cfg.Filter) {
		return
	}
	e.Stats.Observe(fr)
	e.Flows.Observe(fr)
	e.Sessions.Observe(fr)
	e.store(fr)
	if e.hub != nil {
		e.hub.Broadcast("packet", slim(fr))
	}
}

func (e *Engine) store(f *decode.Frame) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.frames) >= e.maxStore {
		e.frames = e.frames[len(e.frames)/4:]
	}
	e.frames = append(e.frames, f)
}

func slim(f *decode.Frame) map[string]any {
	return map[string]any{
		"no": f.No, "timestamp": f.Timestamp, "src": f.Src, "dst": f.Dst,
		"protocol": f.Protocol, "info": f.Info, "length": f.Length,
		"severity": f.Severity, "tags": f.Tags, "meta": f.Meta,
		"flow_key": f.FlowKey,
	}
}

func (e *Engine) ExportJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"stats":    e.Stats.Snapshot(),
		"flows":    e.Flows.Top(100),
		"security": e.Security.Findings(),
		"sessions": e.Sessions.List(100),
		"packets":  e.Frames(),
		"status":   e.Status(),
	})
}

func (e *Engine) ExportCSV(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"no", "time", "src", "dst", "protocol", "length", "info", "flow"})
	for _, fr := range e.Frames() {
		_ = w.Write([]string{
			fmt.Sprintf("%d", fr.No),
			fr.Timestamp.Format(time.RFC3339Nano),
			fr.Src, fr.Dst, fr.Protocol,
			fmt.Sprintf("%d", fr.Length),
			fr.Info,
			fr.FlowKey,
		})
	}
	w.Flush()
	return w.Error()
}

func (e *Engine) Summary() string {
	s := e.Stats.Snapshot()
	mode := e.source
	if mode == "" {
		mode = "file"
	}
	return fmt.Sprintf("[%s] packets=%d bytes=%d pps=%.0f flows=%d sessions=%d findings=%d",
		mode, s.Packets, s.Bytes, s.PPS, e.Flows.Count(), e.Sessions.Count(), len(e.Security.Findings()))
}
