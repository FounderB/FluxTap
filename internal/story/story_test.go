package story_test

import (
	"strings"
	"testing"
	"time"

	"github.com/FounderB/FluxTap/internal/security"
	"github.com/FounderB/FluxTap/internal/session"
	"github.com/FounderB/FluxTap/internal/story"
)

func TestBuildStory(t *testing.T) {
	findings := []security.Finding{
		{Time: time.Unix(1, 0), FrameNo: 10, Severity: "alert", Rule: "port_scan", Message: "scan", Src: "1.1.1.1", Dst: "2.2.2.2"},
		{Time: time.Unix(2, 0), FrameNo: 20, Severity: "alert", Rule: "cleartext_auth", Message: "basic", Src: "1.1.1.1", Dst: "2.2.2.2"},
	}
	sess := []*session.Session{{Key: "TCP|1.1.1.1|2.2.2.2|1|80", Src: "1.1.1.1", Dst: "2.2.2.2"}}
	st := story.Build(findings, sess)
	if len(st.Chapters) != 2 {
		t.Fatalf("chapters=%d", len(st.Chapters))
	}
	if st.Chapters[0].SessionKey == "" {
		t.Fatal("expected session link")
	}
	if !strings.Contains(st.Markdown, "Incident reel") {
		t.Fatalf("markdown: %q", st.Markdown)
	}
}
