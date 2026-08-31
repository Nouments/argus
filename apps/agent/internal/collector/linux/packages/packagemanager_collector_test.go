package packages

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParsePackageOutputs_DpkgAndPacman(t *testing.T) {
	results := map[string]string{
		"dpkg":   "openssl@1.1.1f-1\nnginx@1.18.0-1\n",
		"pacman": "bash 5.1.8-1\ncoreutils 8.32-4\n",
		"snap":   "Name   Version    Rev   Publisher   Notes\ncore   16-2       1234  canonical   -\n",
		"flatpak": "org.gnome.Platform 3.38 1.2\n",
		"dnf":    "bash.x86_64 5.1.8-1.el8@installed\nvim.x86_64 8.2.0-1.el8@installed\n",
		"yum":    "httpd.x86_64 2.4.37-21.el8@installed\n",
		"brew":   "openssl@1.1 1.1.1q\n",
		"apk":    "busybox-1.33.1-r0\n",
	}
	pkgs := parsePackageOutputs(results)
	if len(pkgs) != 11 {
		t.Fatalf("expected 11 packages, got %d", len(pkgs))
	}
	// ensure one dpkg package parsed
	found := false
	for _, p := range pkgs {
		if p.Name == "openssl" && p.Source == "dpkg" {
			found = true
			if p.Version != "1.1.1f-1" {
				t.Fatalf("unexpected version for openssl: %s", p.Version)
			}
		}
	}
	if !found {
		t.Fatalf("openssl dpkg package not found")
	}
	// ensure pacman package present
	found = false
	for _, p := range pkgs {
		if p.Name == "bash" && p.Source == "pacman" {
			found = true
			if p.Version != "5.1.8-1" {
				t.Fatalf("unexpected version for bash: %s", p.Version)
			}
		}
	}
	if !found {
		t.Fatalf("bash pacman package not found")
	}

	// snap parsed
	found = false
	for _, p := range pkgs {
		if p.Source == "snap" && p.Name == "core" {
			found = true
			if p.Version != "16-2" {
				t.Fatalf("unexpected snap core version: %s", p.Version)
			}
		}
	}
	if !found {
		t.Fatalf("snap core package not found")
	}

	// dnf/yum name extraction
	found = false
	for _, p := range pkgs {
		if p.Source == "dnf" && p.Name == "bash" {
			found = true
			if p.Version == "" {
				t.Fatalf("dnf bash version empty")
			}
		}
	}
	if !found {
		t.Fatalf("dnf bash package not found")
	}

	// apk parsing produced something
	found = false
	for _, p := range pkgs {
		if p.Source == "apk" && strings.HasPrefix(p.Name, "busybox") {
			found = true
		}
	}
	if !found {
		t.Fatalf("apk busybox package not found")
	}

	// ensure marshalable
	b, err := json.Marshal(pkgs)
	if err != nil {
		t.Fatalf("marshal packages: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("empty marshal output")
	}
}
