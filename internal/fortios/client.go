// Package fortios is a client for the FortiOS REST API (v2).
package fortios

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultTimeout       = 30 * time.Second
	defaultMaxConcurrent = 4
	defaultRetryBackoff  = 250 * time.Millisecond
	// maxGetAttempts bounds retries of idempotent GETs. Writes are never retried.
	maxGetAttempts = 3
	// maxResponseBytes caps response bodies; full config backups are the largest.
	maxResponseBytes = 64 << 20
)

// Options configures a Client.
type Options struct {
	// Name identifies the device in logs.
	Name string
	// BaseURL is https://host[:port].
	BaseURL string
	Token   string
	// VDOM is used when a call doesn't specify one.
	VDOM               string
	CACertFile         string
	InsecureSkipVerify bool
	Timeout            time.Duration
	// MaxConcurrent limits in-flight requests to the device.
	MaxConcurrent int
	// RetryBackoff is the base delay between GET retries.
	RetryBackoff time.Duration
	Logger       *slog.Logger
	// ReadOnly makes the client refuse every request except GET.
	ReadOnly bool
	// Observer, if set, is called after every non-GET request, whether it
	// succeeded or not. The server uses it for the audit log.
	Observer func(context.Context, Call)
	// OnRequest, if set, is called after every request, including GETs.
	// The server uses it for metrics.
	OnRequest func(context.Context, Call)
}

// Call describes a completed request, for auditing and metrics.
type Call struct {
	Device string
	Method string
	// Path is the API path after /api/v2/, including the escaped mkey.
	Path string
	Mkey string
	VDOM string
	// Body is the JSON request body, if any.
	Body       []byte
	HTTPStatus int
	Revision   string
	Duration   time.Duration
	Err        error
}

// ErrReadOnly is returned for write requests to a read-only device.
var ErrReadOnly = errors.New("fortios: device is configured read-only")

// Client talks to one FortiGate. It is safe for concurrent use.
type Client struct {
	name         string
	baseURL      string
	token        string
	vdom         string
	http         *http.Client
	sem          chan struct{}
	retryBackoff time.Duration
	logger       *slog.Logger
	readOnly     bool
	observer     func(context.Context, Call)
	onRequest    func(context.Context, Call)

	mu   sync.Mutex
	info *Info
}

// New returns a client for one device. It does not contact the device.
func New(opts Options) (*Client, error) {
	u, err := url.Parse(opts.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("fortios: invalid base URL %q", opts.BaseURL)
	}
	if opts.Token == "" {
		return nil, errors.New("fortios: empty API token")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case opts.InsecureSkipVerify:
		tlsConfig.InsecureSkipVerify = true // operator opt-in for lab devices
	case opts.CACertFile != "":
		pem, err := os.ReadFile(opts.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("fortios: reading CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("fortios: no certificates found in %s", opts.CACertFile)
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	c := &Client{
		name:    opts.Name,
		baseURL: "https://" + u.Host,
		token:   opts.Token,
		vdom:    opts.VDOM,
		http: &http.Client{
			Transport: transport,
			Timeout:   orDefault(opts.Timeout, defaultTimeout),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		sem:          make(chan struct{}, orDefault(opts.MaxConcurrent, defaultMaxConcurrent)),
		retryBackoff: orDefault(opts.RetryBackoff, defaultRetryBackoff),
		logger:       opts.Logger,
		readOnly:     opts.ReadOnly,
		observer:     opts.Observer,
		onRequest:    opts.OnRequest,
	}
	if c.logger == nil {
		c.logger = slog.New(slog.DiscardHandler)
	}
	return c, nil
}

// orDefault returns v, or def if v is zero or negative.
func orDefault[T int | time.Duration](v, def T) T {
	if v <= 0 {
		return def
	}
	return v
}

// Params are query parameters common to FortiOS endpoints.
type Params struct {
	// VDOM overrides the client's default VDOM.
	VDOM string
	// Filter entries are ANDed; commas inside one entry are ORed.
	// Example: "name=@web", "action==accept".
	Filter []string
	// Format selects fields to return.
	Format []string
	Start  int
	// Count limits results; 0 means the FortiOS default.
	Count int
	// Extra holds any other query parameters.
	Extra url.Values
}

func (c *Client) query(p *Params) url.Values {
	q := url.Values{}
	if p == nil {
		p = &Params{}
	}
	for k, vs := range p.Extra {
		q[k] = append([]string(nil), vs...)
	}
	if vdom := cmp.Or(p.VDOM, c.vdom); vdom != "" {
		q.Set("vdom", vdom)
	}
	for _, f := range p.Filter {
		q.Add("filter", f)
	}
	if len(p.Format) > 0 {
		q.Set("format", strings.Join(p.Format, "|"))
	}
	if p.Start > 0 {
		q.Set("start", strconv.Itoa(p.Start))
	}
	if p.Count > 0 {
		q.Set("count", strconv.Itoa(p.Count))
	}
	return q
}

// pathRE restricts API paths to FortiOS-style segments: no "..", no query
// strings, no absolute URLs.
var pathRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`)

// ValidatePath reports whether path is an acceptable CMDB/monitor/log path,
// e.g. "firewall/policy" or "firewall.service/custom".
func ValidatePath(path string) error {
	if !pathRE.MatchString(path) {
		return fmt.Errorf("fortios: invalid API path %q", path)
	}
	return nil
}

type request struct {
	method string
	api    string // "cmdb", "monitor" or "log"
	path   string
	mkey   string
	params *Params
	body   any
	// raw accepts a non-JSON success body (e.g. a config backup) in Response.Raw.
	raw bool
}

// apiPath is the request path after /api/v2/, with mkey escaped.
func (r request) apiPath() string {
	p := r.api + "/" + r.path
	if r.mkey != "" {
		p += "/" + url.PathEscape(r.mkey)
	}
	return p
}

func (c *Client) do(ctx context.Context, r request) (*Response, error) {
	if err := ValidatePath(r.path); err != nil {
		return nil, err
	}
	if r.method != http.MethodGet && c.readOnly {
		return nil, ErrReadOnly
	}
	var body []byte
	if r.body != nil {
		var err error
		if body, err = json.Marshal(r.body); err != nil {
			return nil, fmt.Errorf("fortios: encoding request body: %w", err)
		}
	}
	query := c.query(r.params)
	target := c.baseURL + "/api/v2/" + r.apiPath()
	if q := query.Encode(); q != "" {
		target += "?" + q
	}
	audited := r.method != http.MethodGet && c.observer != nil
	if !audited && c.onRequest == nil {
		return c.send(ctx, r, target, body)
	}
	start := time.Now()
	resp, err := c.send(ctx, r, target, body)
	call := Call{
		Device: c.name, Method: r.method, Path: r.apiPath(), Mkey: r.mkey,
		VDOM: query.Get("vdom"), Body: body, Duration: time.Since(start), Err: err,
	}
	var apiErr *APIError
	switch {
	case err == nil:
		call.HTTPStatus, call.Revision = cmp.Or(resp.HTTPStatus, http.StatusOK), resp.Revision
	case errors.As(err, &apiErr):
		call.HTTPStatus = apiErr.HTTPStatus
	}
	if audited {
		c.observer(ctx, call)
	}
	if c.onRequest != nil {
		c.onRequest(ctx, call)
	}
	return resp, err
}

// send acquires a concurrency slot and performs the request with retries.
func (c *Client) send(ctx context.Context, r request, target string, body []byte) (*Response, error) {

	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	attempts := 1
	if r.method == http.MethodGet {
		attempts = maxGetAttempts
	}
	var lastErr error
	for attempt := range attempts {
		if attempt > 0 {
			if err := c.sleep(ctx, attempt); err != nil {
				return nil, err
			}
		}
		resp, retry, err := c.attempt(ctx, r, target, body)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retry {
			break
		}
		c.logger.Debug("fortios retry", "device", c.name, "method", r.method, "path", r.apiPath(), "attempt", attempt+1, "err", err)
	}
	return nil, lastErr
}

// attempt performs one HTTP round trip. retry reports whether a GET may be retried.
func (c *Client) attempt(ctx context.Context, r request, target string, body []byte) (_ *Response, retry bool, _ error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, target, bodyReader)
	if err != nil {
		return nil, false, fmt.Errorf("fortios: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "fortigate-mcp")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, true, fmt.Errorf("fortios: %s %s: %w", r.method, r.apiPath(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, true, fmt.Errorf("fortios: %s %s: reading response: %w", r.method, r.apiPath(), err)
	}
	if len(data) > maxResponseBytes {
		return nil, false, fmt.Errorf("fortios: %s %s: response exceeds %d bytes", r.method, r.apiPath(), maxResponseBytes)
	}
	c.logger.Debug("fortios request", "device", c.name, "method", r.method, "path", r.apiPath(),
		"status", resp.StatusCode, "duration", time.Since(start))

	out, err := c.decode(r, resp.StatusCode, data)
	if err != nil {
		switch resp.StatusCode {
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return nil, true, err
		}
		return nil, false, err
	}
	return out, false, nil
}

func (c *Client) decode(r request, status int, data []byte) (*Response, error) {
	apiErr := &APIError{Method: r.method, Path: r.apiPath(), HTTPStatus: status}

	var resp Response
	if r.raw && status < 400 {
		// A JSON body here is an error envelope; anything else is the payload.
		if json.Unmarshal(data, &resp) == nil && resp.Status == "error" {
			apiErr.Code, apiErr.Message = int(resp.Error), resp.CLIError
			return nil, apiErr
		}
		return &Response{HTTPStatus: status, Raw: data}, nil
	}
	if len(bytes.TrimSpace(data)) == 0 || json.Unmarshal(data, &resp) != nil {
		if status >= 400 {
			return nil, apiErr
		}
		return nil, fmt.Errorf("fortios: %s %s: HTTP %d with non-JSON body", r.method, r.apiPath(), status)
	}
	c.observe(&resp)

	if status >= 400 || resp.Status == "error" {
		if resp.HTTPStatus >= 400 {
			apiErr.HTTPStatus = resp.HTTPStatus
		}
		apiErr.Code = int(resp.Error)
		apiErr.Message = resp.CLIError
		return nil, apiErr
	}
	return &resp, nil
}

func (c *Client) sleep(ctx context.Context, attempt int) error {
	d := c.retryBackoff << (attempt - 1)
	d += rand.N(d/2 + 1) //nolint:gosec // jitter, not security
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Name returns the device name the client was created with.
func (c *Client) Name() string { return c.name }

// VDOM returns the client's default VDOM.
func (c *Client) VDOM() string { return c.vdom }
