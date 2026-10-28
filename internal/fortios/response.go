package fortios

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Response is the FortiOS REST API envelope shared by CMDB, monitor and log
// endpoints. Fields absent from a given response are left zero.
type Response struct {
	HTTPMethod      string          `json:"http_method"`
	Results         json.RawMessage `json:"results"`
	VDOM            string          `json:"vdom"`
	Path            string          `json:"path"`
	Name            string          `json:"name"`
	Action          string          `json:"action"`
	Status          string          `json:"status"`
	HTTPStatus      int             `json:"http_status"`
	Mkey            Mkey            `json:"mkey"`
	Revision        string          `json:"revision"`
	RevisionChanged bool            `json:"revision_changed"`
	OldRevision     string          `json:"old_revision"`
	Size            int             `json:"size"`
	MatchedCount    int             `json:"matched_count"`
	NextIdx         int             `json:"next_idx"`
	LimitReached    bool            `json:"limit_reached"`
	Serial          string          `json:"serial"`
	Version         string          `json:"version"`
	Build           int             `json:"build"`
	Error           ErrorCode       `json:"error"`
	CLIError        string          `json:"cli_error"`
}

// Decode unmarshals Results into v.
func (r *Response) Decode(v any) error {
	if len(r.Results) == 0 {
		return errors.New("fortios: response has no results")
	}
	if err := json.Unmarshal(r.Results, v); err != nil {
		return fmt.Errorf("fortios: decoding results: %w", err)
	}
	return nil
}

// Mkey is an object's primary key, which FortiOS returns as a number for
// some tables (e.g. policy IDs) and a string for others.
type Mkey string

// UnmarshalJSON accepts a JSON string or number.
func (m *Mkey) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*m = Mkey(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("mkey: %w", err)
	}
	*m = Mkey(n.String())
	return nil
}

// ErrorCode is a FortiOS error code (negative integer). It tolerates
// numeric strings and ignores anything else.
type ErrorCode int

// UnmarshalJSON accepts a number or numeric string; other values decode as 0.
func (c *ErrorCode) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	n, err := strconv.Atoi(s)
	if err != nil {
		*c = 0
		return nil //nolint:nilerr // unknown shapes are not fatal
	}
	*c = ErrorCode(n)
	return nil
}

// errorMessages describes common FortiOS error codes. FortiOS also returns
// a cli_error string for many failures, which takes precedence.
//
// TODO(M3): validate against a FortiGate-VM in the integration suite.
var errorMessages = map[int]string{
	-1:  "invalid length of value",
	-2:  "index (value) out of range",
	-3:  "entry not found",
	-4:  "maximum number of entries has been reached",
	-5:  "a duplicate entry already exists",
	-7:  "value conflicts with system settings",
	-8:  "invalid IP address",
	-9:  "invalid IP netmask",
	-14: "permission denied",
	-23: "entry is in use by other objects",
}

// APIError is a failed FortiOS API call.
type APIError struct {
	Method string
	// Path is the API path after /api/v2/, e.g. "cmdb/firewall/policy/5".
	Path       string
	HTTPStatus int
	// Code is the FortiOS error code, or 0 if none was returned.
	Code int
	// Message is the device's CLI error text, if any.
	Message string
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "fortios: %s %s: HTTP %d", e.Method, e.Path, e.HTTPStatus)
	if e.Code != 0 {
		fmt.Fprintf(&b, ", error %d", e.Code)
	}
	if d := e.Description(); d != "" {
		b.WriteString(": ")
		b.WriteString(d)
	}
	return b.String()
}

// Description explains the failure in words, preferring the device's own message.
func (e *APIError) Description() string {
	if e.Message != "" {
		return e.Message
	}
	if m, ok := errorMessages[e.Code]; ok {
		return m
	}
	switch e.HTTPStatus {
	case http.StatusUnauthorized:
		return "API token rejected; check the token and that this server's address is in the API admin's trusted hosts"
	case http.StatusForbidden:
		return "the API admin's profile does not permit this operation"
	case http.StatusNotFound:
		return "not found"
	case http.StatusMethodNotAllowed:
		return "method not allowed on this endpoint"
	case http.StatusTooManyRequests:
		return "rate limited by the FortiGate"
	}
	return http.StatusText(e.HTTPStatus)
}

// IsNotFound reports whether err is a FortiOS "not found" error.
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && (e.HTTPStatus == http.StatusNotFound || e.Code == -3)
}
