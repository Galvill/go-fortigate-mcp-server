// Package fakefgt is an in-memory FortiGate REST API for tests.
//
// It implements enough of FortiOS 7.x's /api/v2 surface for client and tool
// tests: CMDB CRUD with filter/format/paging and policy moves, canned monitor
// responses, bearer auth and failure injection. Response envelopes follow the
// FortiOS 7.4 format.
package fakefgt

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Defaults reported in every response envelope.
const (
	DefaultToken    = "fake-token"
	DefaultVersion  = "v7.4.4"
	DefaultBuild    = 2662
	DefaultSerial   = "FGVM00FAKE000001"
	DefaultHostname = "FGVM-FAKE"
)

// mkeyFields lists tables whose primary key isn't "name". Numeric keys are
// assigned automatically when omitted on create.
var mkeyFields = map[string]string{
	"firewall/policy":  "policyid",
	"firewall/policy6": "policyid",
	"router/static":    "seq-num",
	"router/static6":   "seq-num",
}

// Request is a recorded API call.
type Request struct {
	Method string
	// Path is the escaped path after /api/v2/.
	Path  string
	Query url.Values
	Body  []byte
}

type failure struct {
	method, path string
	status       int
	remaining    int
}

// Server is a fake FortiGate. Create it with New.
type Server struct {
	*httptest.Server
	Token string

	mu         sync.Mutex
	tables     map[string][]map[string]any // key: vdom + "|" + path
	singletons map[string]map[string]any   // key: vdom + "|" + path
	nextID     map[string]int
	canned     map[string]any // key: "monitor/<path>" or "log/<path>"
	failures   []*failure
	requests   []Request
	revision   int
}

// New starts a TLS fake FortiGate that is closed when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{
		Token:      DefaultToken,
		tables:     map[string][]map[string]any{},
		singletons: map[string]map[string]any{},
		nextID:     map[string]int{},
		canned: map[string]any{
			"monitor/system/status": map[string]any{
				"model_name":      "FortiGate",
				"model_number":    "VM64",
				"model":           "FGVM64",
				"hostname":        DefaultHostname,
				"log_disk_status": "available",
			},
		},
	}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

// WriteCACert writes the server's certificate as PEM and returns the path.
func (s *Server) WriteCACert(t testing.TB) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fakefgt-ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// SetMonitor sets the results returned for a monitor path (GET or POST).
func (s *Server) SetMonitor(path string, results any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.canned["monitor/"+path] = results
}

// SetLog sets the results returned for a log path such as "disk/event/system".
func (s *Server) SetLog(path string, results any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.canned["log/"+path] = results
}

// download is a canned non-JSON response body, such as a config backup.
type download []byte

// SetDownload sets a raw (non-JSON) body returned for a monitor path.
func (s *Server) SetDownload(path string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.canned["monitor/"+path] = download(body)
}

// Singleton returns a copy of a single-object CMDB table, or nil.
func (s *Server) Singleton(vdom, path string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if obj := s.singletons[vdom+"|"+path]; obj != nil {
		return clone(obj)
	}
	return nil
}

// SetSingleton sets the object returned for a single-object CMDB table such
// as system/sdwan.
func (s *Server) SetSingleton(vdom, path string, obj map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.singletons[vdom+"|"+path] = clone(obj)
}

// Seed appends entries to a CMDB table.
func (s *Server) Seed(vdom, path string, entries ...map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entries {
		s.insert(vdom, path, clone(e))
	}
}

// Entries returns a copy of a CMDB table.
func (s *Server) Entries(vdom, path string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, e := range s.tables[vdom+"|"+path] {
		out = append(out, clone(e))
	}
	return out
}

// FailNext makes the next n requests matching method and path (after
// /api/v2/, without query) fail with status.
func (s *Server) FailNext(method, path string, status, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, &failure{method, path, status, n})
}

// Requests returns the calls received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.Token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	rest, ok := strings.CutPrefix(r.URL.EscapedPath(), "/api/v2/")
	if !ok {
		http.NotFound(w, r)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: rest, Query: r.URL.Query(), Body: body})

	for _, f := range s.failures {
		if f.remaining > 0 && f.method == r.Method && f.path == rest {
			f.remaining--
			w.WriteHeader(f.status)
			return
		}
	}

	vdom := r.URL.Query().Get("vdom")
	if vdom == "" {
		vdom = "root"
	}
	api, path, _ := strings.Cut(rest, "/")
	switch api {
	case "cmdb":
		s.cmdb(w, r, vdom, path, body)
	case "monitor", "log":
		s.cannedCall(w, r, vdom, api, path)
	default:
		s.reply(w, http.StatusNotFound, s.envelope(r.Method, vdom, path, map[string]any{"status": "error"}))
	}
}

func (s *Server) envelope(method, vdom, path string, fields map[string]any) map[string]any {
	category, name, _ := strings.Cut(path, "/")
	env := map[string]any{
		"http_method": method,
		"vdom":        vdom,
		"path":        category,
		"name":        name,
		"status":      "success",
		"http_status": http.StatusOK,
		"serial":      DefaultSerial,
		"version":     DefaultVersion,
		"build":       DefaultBuild,
	}
	for k, v := range fields {
		env[k] = v
	}
	return env
}

func (s *Server) reply(w http.ResponseWriter, status int, env map[string]any) {
	if status != http.StatusOK {
		env["status"] = "error"
		env["http_status"] = status
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, vdom, path string, status, code int, cliErr string) {
	fields := map[string]any{}
	if code != 0 {
		fields["error"] = code
	}
	if cliErr != "" {
		fields["cli_error"] = cliErr
	}
	s.reply(w, status, s.envelope(r.Method, vdom, path, fields))
}

func (s *Server) cannedCall(w http.ResponseWriter, r *http.Request, vdom, api, path string) {
	results, ok := s.canned[api+"/"+path]
	if !ok {
		s.fail(w, r, vdom, path, http.StatusNotFound, 0, "")
		return
	}
	if raw, ok := results.(download); ok {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(raw)
		return
	}
	s.reply(w, http.StatusOK, s.envelope(r.Method, vdom, path, map[string]any{"results": results}))
}

func (s *Server) cmdb(w http.ResponseWriter, r *http.Request, vdom, rest string, body []byte) {
	segs := strings.Split(rest, "/")
	if len(segs) < 2 {
		s.fail(w, r, vdom, rest, http.StatusNotFound, 0, "")
		return
	}
	path := segs[0] + "/" + segs[1]
	var mkey string
	if len(segs) > 2 {
		var err error
		if mkey, err = url.PathUnescape(segs[2]); err != nil {
			s.fail(w, r, vdom, path, http.StatusBadRequest, 0, "")
			return
		}
	}
	key := vdom + "|" + path
	q := r.URL.Query()

	switch {
	case r.Method == http.MethodGet && q.Get("action") == "schema":
		s.reply(w, http.StatusOK, s.envelope(r.Method, vdom, path, map[string]any{
			"results": map[string]any{"name": segs[1], "category": "table", "mkey": mkeyField(path), "children": map[string]any{}},
		}))

	case r.Method == http.MethodGet && mkey == "" && s.singletons[key] != nil:
		s.reply(w, http.StatusOK, s.envelope(r.Method, vdom, path, map[string]any{
			"results": clone(s.singletons[key]), "revision": s.rev(),
		}))

	case r.Method == http.MethodGet && mkey == "":
		matched := filter(s.tables[key], q["filter"])
		page := paginate(matched, q.Get("start"), q.Get("count"))
		results := make([]map[string]any, 0, len(page))
		for _, e := range page {
			results = append(results, selectFields(e, q.Get("format")))
		}
		s.reply(w, http.StatusOK, s.envelope(r.Method, vdom, path, map[string]any{
			"results": results, "size": len(results), "matched_count": len(matched),
			"revision": s.rev(),
		}))

	case r.Method == http.MethodGet:
		i := s.find(key, path, mkey)
		if i < 0 {
			s.fail(w, r, vdom, path, http.StatusNotFound, -3, "")
			return
		}
		s.reply(w, http.StatusOK, s.envelope(r.Method, vdom, path, map[string]any{
			"results": []any{selectFields(s.tables[key][i], q.Get("format"))}, "size": 1, "matched_count": 1,
			"revision": s.rev(),
		}))

	case r.Method == http.MethodPost && mkey == "":
		var entry map[string]any
		if err := json.Unmarshal(body, &entry); err != nil {
			s.fail(w, r, vdom, path, http.StatusBadRequest, 0, "invalid JSON")
			return
		}
		if id, ok := entry[mkeyField(path)]; ok && s.find(key, path, str(id)) >= 0 {
			s.fail(w, r, vdom, path, http.StatusInternalServerError, -5, "")
			return
		}
		e := s.insert(vdom, path, entry)
		s.changed(w, r, vdom, path, e[mkeyField(path)])

	case r.Method == http.MethodPut && mkey == "":
		var patch map[string]any
		if err := json.Unmarshal(body, &patch); err != nil {
			s.fail(w, r, vdom, path, http.StatusBadRequest, 0, "invalid JSON")
			return
		}
		if s.singletons[key] == nil {
			s.singletons[key] = map[string]any{}
		}
		for k, v := range patch {
			s.singletons[key][k] = v
		}
		s.changed(w, r, vdom, path, nil)

	case r.Method == http.MethodPut && mkey != "" && q.Get("action") == "move":
		s.move(w, r, vdom, path, mkey)

	case r.Method == http.MethodPut && mkey != "":
		i := s.find(key, path, mkey)
		if i < 0 {
			s.fail(w, r, vdom, path, http.StatusNotFound, -3, "")
			return
		}
		var patch map[string]any
		if err := json.Unmarshal(body, &patch); err != nil {
			s.fail(w, r, vdom, path, http.StatusBadRequest, 0, "invalid JSON")
			return
		}
		mk := s.tables[key][i][mkeyField(path)]
		if _, numeric := mkeyFields[path]; !numeric {
			// Name-keyed entries can be renamed by sending a new name.
			if name, ok := patch["name"]; ok && str(name) != mkey {
				if s.find(key, path, str(name)) >= 0 {
					s.fail(w, r, vdom, path, http.StatusInternalServerError, -5, "")
					return
				}
				mk = name
			}
		}
		for k, v := range patch {
			s.tables[key][i][k] = v
		}
		s.tables[key][i][mkeyField(path)] = mk
		s.changed(w, r, vdom, path, mk)

	case r.Method == http.MethodDelete && mkey != "":
		i := s.find(key, path, mkey)
		if i < 0 {
			s.fail(w, r, vdom, path, http.StatusNotFound, -3, "")
			return
		}
		mk := s.tables[key][i][mkeyField(path)]
		s.tables[key] = slices.Delete(s.tables[key], i, i+1)
		s.changed(w, r, vdom, path, mk)

	default:
		s.fail(w, r, vdom, path, http.StatusMethodNotAllowed, 0, "")
	}
}

func (s *Server) move(w http.ResponseWriter, r *http.Request, vdom, path, mkey string) {
	key := vdom + "|" + path
	q := r.URL.Query()
	target, after := q.Get("before"), false
	if target == "" {
		target, after = q.Get("after"), true
	}
	i, j := s.find(key, path, mkey), s.find(key, path, target)
	if i < 0 || j < 0 {
		s.fail(w, r, vdom, path, http.StatusNotFound, -3, "")
		return
	}
	entry := s.tables[key][i]
	s.tables[key] = slices.Delete(s.tables[key], i, i+1)
	j = s.find(key, path, target)
	if after {
		j++
	}
	s.tables[key] = slices.Insert(s.tables[key], j, entry)
	s.changed(w, r, vdom, path, entry[mkeyField(path)])
}

func (s *Server) changed(w http.ResponseWriter, r *http.Request, vdom, path string, mkey any) {
	old := s.rev()
	s.revision++
	s.reply(w, http.StatusOK, s.envelope(r.Method, vdom, path, map[string]any{
		"mkey": mkey, "revision": s.rev(), "old_revision": old, "revision_changed": true,
	}))
}

func (s *Server) rev() string { return fmt.Sprintf("%032x", s.revision) }

// insert assigns a numeric mkey if the table uses one and it's missing.
// The caller holds s.mu.
func (s *Server) insert(vdom, path string, e map[string]any) map[string]any {
	key := vdom + "|" + path
	field := mkeyField(path)
	if _, numeric := mkeyFields[path]; numeric {
		if id, ok := e[field]; !ok || str(id) == "0" {
			s.nextID[key]++
			for s.find(key, path, strconv.Itoa(s.nextID[key])) >= 0 {
				s.nextID[key]++
			}
			e[field] = float64(s.nextID[key])
		} else if n, err := strconv.Atoi(str(id)); err == nil && n > s.nextID[key] {
			s.nextID[key] = n
		}
	}
	s.tables[key] = append(s.tables[key], e)
	return e
}

func (s *Server) find(key, path, mkey string) int {
	field := mkeyField(path)
	return slices.IndexFunc(s.tables[key], func(e map[string]any) bool { return str(e[field]) == mkey })
}

func mkeyField(path string) string {
	if f, ok := mkeyFields[path]; ok {
		return f
	}
	return "name"
}

// str renders scalar JSON values the way FortiOS compares them.
func str(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// values flattens a field for filtering: scalars as-is, and lists of
// objects by their "name" (as in policy srcaddr/dstaddr).
func values(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return []string{str(v)}
	}
	var out []string
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, str(m["name"]))
		} else {
			out = append(out, str(item))
		}
	}
	return out
}

// filter applies FortiOS filters: separate filters AND, comma-separated
// clauses within one OR. Supports ==, !=, =@ (contains) and !@.
func filter(entries []map[string]any, filters []string) []map[string]any {
	var out []map[string]any
	for _, e := range entries {
		ok := true
		for _, f := range filters {
			if !slices.ContainsFunc(strings.Split(f, ","), func(c string) bool { return matches(e, c) }) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, e)
		}
	}
	return out
}

func matches(e map[string]any, clause string) bool {
	for _, op := range []string{"==", "!=", "=@", "!@"} {
		field, want, found := strings.Cut(clause, op)
		if !found {
			continue
		}
		vals := values(e[field])
		switch op {
		case "==":
			return slices.Contains(vals, want)
		case "!=":
			return !slices.Contains(vals, want)
		case "=@":
			return slices.ContainsFunc(vals, func(v string) bool { return strings.Contains(v, want) })
		case "!@":
			return !slices.ContainsFunc(vals, func(v string) bool { return strings.Contains(v, want) })
		}
	}
	return false
}

func paginate(entries []map[string]any, start, count string) []map[string]any {
	from, _ := strconv.Atoi(start)
	from = min(max(from, 0), len(entries))
	to := len(entries)
	if n, err := strconv.Atoi(count); err == nil && n > 0 {
		to = min(from+n, len(entries))
	}
	return entries[from:to]
}

func selectFields(e map[string]any, format string) map[string]any {
	if format == "" {
		return clone(e)
	}
	out := map[string]any{}
	for _, f := range strings.Split(format, "|") {
		if v, ok := e[f]; ok {
			out[f] = v
		}
	}
	return out
}

func clone(e map[string]any) map[string]any {
	data, _ := json.Marshal(e)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out
}
