package fortios

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Version is a FortiOS version such as 7.4.4.
type Version struct {
	Major, Minor, Patch int
}

// ParseVersion parses "v7.4.4" or "7.4.4".
func ParseVersion(s string) (Version, error) {
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("fortios: invalid version %q", s)
	}
	var nums [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, fmt.Errorf("fortios: invalid version %q", s)
		}
		nums[i] = n
	}
	return Version{nums[0], nums[1], nums[2]}, nil
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// AtLeast reports whether v >= major.minor.patch.
func (v Version) AtLeast(major, minor, patch int) bool {
	if v.Major != major {
		return v.Major > major
	}
	if v.Minor != minor {
		return v.Minor > minor
	}
	return v.Patch >= patch
}

// Info identifies the firmware and serial of a device, taken from the
// envelope that every FortiOS response carries.
type Info struct {
	Version Version
	Build   int
	Serial  string
}

// observe caches device info from any response that carries it.
func (c *Client) observe(r *Response) {
	if r.Version == "" {
		return
	}
	v, err := ParseVersion(r.Version)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.info = &Info{Version: v, Build: r.Build, Serial: r.Serial}
	c.mu.Unlock()
}

// Info returns the device's firmware info, calling the device only if no
// response has been seen yet.
func (c *Client) Info(ctx context.Context) (Info, error) {
	c.mu.Lock()
	info := c.info
	c.mu.Unlock()
	if info != nil {
		return *info, nil
	}
	st, err := c.Status(ctx)
	if err != nil {
		return Info{}, err
	}
	return st.Info, nil
}

// SystemStatus is the result of monitor/system/status.
type SystemStatus struct {
	Info
	Hostname      string `json:"hostname"`
	ModelName     string `json:"model_name"`
	ModelNumber   string `json:"model_number"`
	Model         string `json:"model"`
	LogDiskStatus string `json:"log_disk_status"`
}

// Status fetches monitor/system/status. It always calls the device.
func (c *Client) Status(ctx context.Context) (*SystemStatus, error) {
	resp, err := c.MonitorGet(ctx, "system/status", nil)
	if err != nil {
		return nil, err
	}
	var st SystemStatus
	if err := resp.Decode(&st); err != nil {
		return nil, err
	}
	v, err := ParseVersion(resp.Version)
	if err != nil {
		return nil, err
	}
	st.Info = Info{Version: v, Build: resp.Build, Serial: resp.Serial}
	return &st, nil
}
