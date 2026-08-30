package host

import (
	"runtime"
	"testing"
)

func TestDetectkHost(t *testing.T) {
	host, err := DetectkHost()
	if err != nil {
		t.Fatalf("DetectkHost() returned an error: %v", err)
	}

	if host == nil {
		t.Fatal("DetectkHost() returned nil host")
	}

	if host.OS != runtime.GOOS {
		t.Errorf(
			"DetectkHost() OS = %q, want %q",
			host.OS,
			runtime.GOOS,
		)
	}

	if host.Arch != runtime.GOARCH {
		t.Errorf(
			"DetectkHost() Arch = %q, want %q",
			host.Arch,
			runtime.GOARCH,
		)
	}
}

func TestGetMetadata(t *testing.T) {
	metadata, err := GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata() returned an error: %v", err)
	}

	if metadata == nil {
		t.Fatal("GetMetadata() returned nil metadata")
	}

	if metadata.Hostname == "" {
		t.Error("GetMetadata() returned an empty hostname")
	}

	if metadata.Interfaces == nil {
		t.Error("GetMetadata() returned nil interfaces")
	}
}

func TestGetMetadataInterfaces(t *testing.T) {
	metadata, err := GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata() returned an error: %v", err)
	}

	for _, iface := range metadata.Interfaces {
		if iface.Name == "" {
			t.Error("found an interface with an empty name")
		}

		if iface.Index <= 0 {
			t.Errorf(
				"interface %q has invalid index: %d",
				iface.Name,
				iface.Index,
			)
		}
	}
}