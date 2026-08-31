package logs

import "testing"

func TestParseSyslogLine(t *testing.T) {
	entry, err := ParseSyslogLine("Aug 21 12:34:56 host sshd[123]: Failed password for invalid user root from 1.2.3.4")
	if err != nil {
		t.Fatalf("ParseSyslogLine returned error: %v", err)
	}
	if entry.Host != "host" {
		t.Fatalf("ParseSyslogLine host = %q, want %q", entry.Host, "host")
	}
	if entry.Program != "sshd" {
		t.Fatalf("ParseSyslogLine program = %q, want %q", entry.Program, "sshd")
	}
	if entry.Message == "" {
		t.Fatal("ParseSyslogLine message should not be empty")
	}
}
