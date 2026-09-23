package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// JailStatus holds the real-time status parsed from fail2ban-client
type JailStatus struct {
	Jail           string   `json:"jail"`
	CurrentlyBanned int     `json:"currently_banned"`
	TotalBanned    int      `json:"total_banned"`
	CurrentlyFailed int     `json:"currently_failed"`
	TotalFailed    int      `json:"total_failed"`
	BannedIPList   []string `json:"banned_ip_list"`
}

// Client wraps interactions with fail2ban
type Client struct {
	socketPath string
	clientBin  string
}

// NewClient creates a new fail2ban IPC client
func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = "/var/run/fail2ban/fail2ban.sock"
	}
	bin, err := exec.LookPath("fail2ban-client")
	if err != nil {
		bin = "fail2ban-client"
	}
	return &Client{
		socketPath: socketPath,
		clientBin:  bin,
	}
}

// ValidateIP ensures an IP address is syntactically valid (IPv4 or IPv6)
func ValidateIP(ipStr string) (string, error) {
	clean := strings.TrimSpace(ipStr)
	parsed := net.ParseIP(clean)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP address format: %q", ipStr)
	}
	return parsed.String(), nil
}

// Ping tests connection to the fail2ban server socket
func (c *Client) Ping(ctx context.Context) (bool, error) {
	out, err := c.run(ctx, "ping")
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(out), "pong"), nil
}

// GetStatus queries the status of a specific jail (e.g. "traefik-401")
func (c *Client) GetStatus(ctx context.Context, jail string) (*JailStatus, error) {
	if jail == "" {
		jail = "traefik-401"
	}
	out, err := c.run(ctx, "status", jail)
	if err != nil {
		return nil, fmt.Errorf("failed to get status for jail %s: %w", jail, err)
	}

	return parseJailStatus(jail, out)
}

// UnbanIP validates the IP and instructs fail2ban to remove the ban
func (c *Client) UnbanIP(ctx context.Context, jail, rawIP string) error {
	ip, err := ValidateIP(rawIP)
	if err != nil {
		return err
	}
	if jail == "" {
		jail = "traefik-401"
	}

	out, err := c.run(ctx, "set", jail, "unbanip", ip)
	if err != nil {
		return fmt.Errorf("unban command failed for %s on %s: %w (output: %s)", ip, jail, err, out)
	}
	return nil
}

// BanIP validates the IP and instructs fail2ban to ban it
func (c *Client) BanIP(ctx context.Context, jail, rawIP string) error {
	ip, err := ValidateIP(rawIP)
	if err != nil {
		return err
	}
	if jail == "" {
		jail = "traefik-401"
	}

	out, err := c.run(ctx, "set", jail, "banip", ip)
	if err != nil {
		return fmt.Errorf("ban command failed for %s on %s: %w (output: %s)", ip, jail, err, out)
	}
	return nil
}

func (c *Client) run(ctx context.Context, args ...string) (string, error) {
	fullArgs := append([]string{"-s", c.socketPath}, args...)
	cmd := exec.CommandContext(ctx, c.clientBin, fullArgs...)
	out, err := cmd.CombinedOutput()
	outputStr := string(out)
	if err != nil {
		return outputStr, fmt.Errorf("fail2ban-client %s exited with %v: %s", strings.Join(args, " "), err, outputStr)
	}
	return outputStr, nil
}

var (
	reCurrentlyBanned = regexp.MustCompile(`Currently banned:\s+(\d+)`)
	reTotalBanned     = regexp.MustCompile(`Total banned:\s+(\d+)`)
	reCurrentlyFailed = regexp.MustCompile(`Currently failed:\s+(\d+)`)
	reTotalFailed     = regexp.MustCompile(`Total failed:\s+(\d+)`)
	reBannedIPList    = regexp.MustCompile(`Banned IP list:\s*(.*)`)
)

func parseJailStatus(jail, output string) (*JailStatus, error) {
	if output == "" {
		return nil, errors.New("empty output from fail2ban-client")
	}

	status := &JailStatus{
		Jail:         jail,
		BannedIPList: []string{},
	}

	if m := reCurrentlyBanned.FindStringSubmatch(output); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &status.CurrentlyBanned)
	}
	if m := reTotalBanned.FindStringSubmatch(output); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &status.TotalBanned)
	}
	if m := reCurrentlyFailed.FindStringSubmatch(output); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &status.CurrentlyFailed)
	}
	if m := reTotalFailed.FindStringSubmatch(output); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &status.TotalFailed)
	}

	if m := reBannedIPList.FindStringSubmatch(output); len(m) > 1 {
		rawIPs := strings.TrimSpace(m[1])
		if rawIPs != "" {
			for _, part := range strings.Fields(rawIPs) {
				clean := strings.Trim(part, ", ")
				if clean != "" {
					status.BannedIPList = append(status.BannedIPList, clean)
				}
			}
		}
	}

	return status, nil
}
