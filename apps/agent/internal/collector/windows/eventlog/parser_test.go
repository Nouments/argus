package eventlog

import (
	"testing"
)

func TestParseWinRecord_Basic(t *testing.T) {
	parts := []string{`Provider Name:  Microsoft-Windows-Security-Auditing
EventID: 4625
Level: 0
Task: 12544
Keywords: 0x8020000000000000`, `Provider Name:  Example-Provider
EventID: 1000
Message: Test event message`}

	if got := parseWinRecord(parts[0]); got["provider_name"] != "Microsoft-Windows-Security-Auditing" {
		t.Fatalf("expected provider_name parsed, got %q", got["provider_name"])
	}
	if got := parseWinRecord(parts[0]); got["eventid"] != "4625" {
		t.Fatalf("expected eventid 4625, got %q", got["eventid"])
	}
	p2 := parseWinRecord(parts[1])
	if p2["provider_name"] != "Example-Provider" {
		t.Fatalf("expected Example-Provider, got %q", p2["provider_name"])
	}
	if p2["message"] != "Test event message" {
		t.Fatalf("expected message parsed, got %q", p2["message"])
	}
}
