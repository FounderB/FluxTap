package stats

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/FounderB/FluxTap/internal/decode"
)

type Snapshot struct {
	Packets       uint64            `json:"packets"`
	Bytes         uint64            `json:"bytes"`
	PPS           float64           `json:"pps"`
	BPS           float64           `json:"bps"`
	Protocols     map[string]uint64 `json:"protocols"`
	TopTalkers    []Talker          `json:"top_talkers"`
	Ports         map[string]uint64 `json:"ports"`
	Severity      map[string]uint64 `json:"severity"`
	StartedAt     time.Time         `json:"started_at"`
	ElapsedSec    float64           `json:"elapsed_sec"`
	AvgPacketSize float64           `json:"avg_packet_size"`
	Timeline      []Bucket          `json:"timeline"`
}

type Talker struct {
	Addr    string `json:"addr"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type Bucket struct {
	T       int64  `json:"t"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type Engine struct {
	packets   atomic.Uint64
	bytes     atomic.Uint64
	started   time.Time
	mu        sync.Mutex
	protocols map[string]uint64
	talkers   map[string]*Talker
	ports     map[string]uint64
	severity map[string]uint64
	timeline  []Bucket
	bucketSec int64
}

func New() *Engine {
	return &Engine{
		started:   time.Now(),
		protocols: map[string]uint64{},
		talkers:   map[string]*Talker{},
		ports:     map[string]uint64{},
		severity: map[string]uint64{},
		timeline:  make([]Bucket, 0, 256),
	}
}

func (e *Engine) Observe(f *decode.Frame) {
	e.packets.Add(1)
	e.bytes.Add(uint64(f.Length))
	e.mu.Lock()
	defer e.mu.Unlock()
	e.protocols[f.Protocol]++
	if f.Severity == "" {
		e.severity["info"]++
	} else {
		e.severity[f.Severity]++
	}
	for _, addr := range []string{f.Meta["ip_src"], f.Meta["ip_dst"]} {
		if addr == "" {
			continue
		}
		t := e.talkers[addr]
		if t == nil {
			t = &Talker{Addr: addr}
			e.talkers[addr] = t
		}
		t.Packets++
		t.Bytes += uint64(f.Length)
	}
	if p := f.Meta["dport"]; p != "" {
		e.ports[p]++
	}
	sec := f.Timestamp.Unix()
	if sec == 0 {
		sec = time.Now().Unix()
	}
	if len(e.timeline) == 0 || e.timeline[len(e.timeline)-1].T != sec {
		e.timeline = append(e.timeline, Bucket{T: sec})
		if len(e.timeline) > 600 {
			e.timeline = e.timeline[len(e.timeline)-600:]
		}
	}
	e.timeline[len(e.timeline)-1].Packets++
	e.timeline[len(e.timeline)-1].Bytes += uint64(f.Length)
}

func (e *Engine) Snapshot() Snapshot {
	pkts := e.packets.Load()
	bts := e.bytes.Load()
	elapsed := time.Since(e.started).Seconds()
	if elapsed < 0.001 {
		elapsed = 0.001
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	proto := make(map[string]uint64, len(e.protocols))
	for k, v := range e.protocols {
		proto[k] = v
	}
	ports := make(map[string]uint64, len(e.ports))
	for k, v := range e.ports {
		ports[k] = v
	}
	sev := make(map[string]uint64, len(e.severity))
	for k, v := range e.severity {
		sev[k] = v
	}
	talkers := make([]Talker, 0, len(e.talkers))
	for _, t := range e.talkers {
		talkers = append(talkers, *t)
	}
	// sort by bytes
	for i := 0; i < len(talkers); i++ {
		max := i
		for j := i + 1; j < len(talkers); j++ {
			if talkers[j].Bytes > talkers[max].Bytes {
				max = j
			}
		}
		talkers[i], talkers[max] = talkers[max], talkers[i]
	}
	if len(talkers) > 15 {
		talkers = talkers[:15]
	}
	tl := make([]Bucket, len(e.timeline))
	copy(tl, e.timeline)
	avg := 0.0
	if pkts > 0 {
		avg = float64(bts) / float64(pkts)
	}
	return Snapshot{
		Packets:       pkts,
		Bytes:         bts,
		PPS:           float64(pkts) / elapsed,
		BPS:           float64(bts) * 8 / elapsed,
		Protocols:     proto,
		TopTalkers:    talkers,
		Ports:         ports,
		Severity:      sev,
		StartedAt:     e.started,
		ElapsedSec:    elapsed,
		AvgPacketSize: avg,
		Timeline:      tl,
	}
}

func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.packets.Store(0)
	e.bytes.Store(0)
	e.started = time.Now()
	e.protocols = map[string]uint64{}
	e.talkers = map[string]*Talker{}
	e.ports = map[string]uint64{}
	e.severity = map[string]uint64{}
	e.timeline = e.timeline[:0]
}
