package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
)

func decode(t *testing.T, buf *bytes.Buffer) []Record {
	t.Helper()
	var recs []Record
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		recs = append(recs, r)
	}
	return recs
}

func TestObserve(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, false, nil)
	l.now = func() time.Time { return time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC) }

	info := &Info{Tool: "fgt_policy_create", SessionID: "s1"}
	ctx := WithInfo(context.Background(), info)
	l.Observe(ctx, fortios.Call{
		Device: "hq", VDOM: "root", Method: "POST", Path: "cmdb/firewall/policy",
		Body: []byte(`{"name":"p"}`), HTTPStatus: 200, Revision: "abc", Duration: 1500 * time.Millisecond,
	})
	info.ConfirmedHostname = "fw-hq"
	l.Observe(ctx, fortios.Call{Device: "hq", Method: "POST", Path: "monitor/system/os/reboot", HTTPStatus: 500, Err: errors.New("boom")})

	recs := decode(t, &buf)
	if len(recs) != 2 {
		t.Fatalf("records = %d", len(recs))
	}
	r := recs[0]
	if r.Tool != "fgt_policy_create" || r.SessionID != "s1" || r.Device != "hq" || r.Result != "ok" || r.Revision != "abc" ||
		r.DurationMS != 1500 || r.BodySHA256 == "" || r.Body != nil || !r.Time.Equal(l.now()) {
		t.Errorf("record = %+v", r)
	}
	if r := recs[1]; r.Result != "error" || r.Error != "boom" || r.HTTPStatus != 500 || r.ConfirmedHostname != "fw-hq" {
		t.Errorf("error record = %+v", r)
	}
}

func TestBodiesRedacted(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, true, nil)
	l.Observe(context.Background(), fortios.Call{
		Device: "hq", Method: "POST", Path: "cmdb/vpn.ipsec/phase1-interface",
		Body: []byte(`{"name":"t1","psksecret":"hunter2"}`),
	})
	out := buf.String()
	if strings.Contains(out, "hunter2") || !strings.Contains(out, `"name":"t1"`) {
		t.Errorf("audit line = %s", out)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriteFailureDoesNotPanic(t *testing.T) {
	New(failWriter{}, false, nil).Observe(context.Background(), fortios.Call{Device: "hq", Method: "DELETE"})
}
