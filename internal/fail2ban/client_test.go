package fail2ban

import (
	"testing"
)

func TestValidateIP(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		shouldError bool
	}{
		{"192.168.1.1", "192.168.1.1", false},
		{" 20.25.34.42 ", "20.25.34.42", false},
		{"::1", "::1", false},
		{"2001:db8::1", "2001:db8::1", false},
		{"192.168.1.300", "", true},
		{"not-an-ip", "", true},
		{"1.1.1.1; rm -rf /", "", true},
		{"1.1.1.1 && whoami", "", true},
		{"1.1.1.1\ncat /etc/passwd", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		got, err := ValidateIP(tt.input)
		if (err != nil) != tt.shouldError {
			t.Errorf("ValidateIP(%q) error = %v, shouldError = %v", tt.input, err, tt.shouldError)
			continue
		}
		if got != tt.expected {
			t.Errorf("ValidateIP(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseJailStatus(t *testing.T) {
	rawOutput := "Status for the jail: traefik-401\n" +
		"|- Filter\n" +
		"|  |- Currently failed:\t2\n" +
		"|  |- Total failed:\t15\n" +
		"|  `- File list:\t/var/log/traefik/access.log\n" +
		"`- Actions\n" +
		"   |- Currently banned:\t2\n" +
		"   |- Total banned:\t5\n" +
		"   `- Banned IP list:\t20.25.34.42 198.51.100.99\n"

	status, err := parseJailStatus("traefik-401", rawOutput)
	if err != nil {
		t.Fatalf("unexpected error parsing status: %v", err)
	}

	if status.CurrentlyBanned != 2 {
		t.Errorf("expected CurrentlyBanned 2, got %d", status.CurrentlyBanned)
	}
	if status.TotalBanned != 5 {
		t.Errorf("expected TotalBanned 5, got %d", status.TotalBanned)
	}
	if status.CurrentlyFailed != 2 {
		t.Errorf("expected CurrentlyFailed 2, got %d", status.CurrentlyFailed)
	}
	if status.TotalFailed != 15 {
		t.Errorf("expected TotalFailed 15, got %d", status.TotalFailed)
	}
	if len(status.BannedIPList) != 2 {
		t.Fatalf("expected 2 banned IPs, got %d", len(status.BannedIPList))
	}
	if status.BannedIPList[0] != "20.25.34.42" || status.BannedIPList[1] != "198.51.100.99" {
		t.Errorf("unexpected IP list: %v", status.BannedIPList)
	}
}
