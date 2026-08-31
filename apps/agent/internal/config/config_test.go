package config

import (
	"reflect"
	"testing"
)

func TestExportPathByOS(t *testing.T) {
	if got := ExportPathByOS("linux"); got != "/etc/argus/config/agent.yaml" {
		t.Fatalf("ExportPathByOS(linux) = %q, want %q", got, "/etc/argus/config/agent.yaml")
	}
	if got := ExportPathByOS("windows"); got != `C:\ProgramData\Argus\config\agent.yaml` {
		t.Fatalf("ExportPathByOS(windows) = %q, want %q", got, `C:\ProgramData\Argus\config\agent.yaml`)
	}
}

func TestFilesystemPath(t *testing.T) {
	got, err := FilesystemPath("/tmp/a, /tmp/b ; /tmp/c")
	if err != nil {
		t.Fatalf("FilesystemPath returned error: %v", err)
	}
	want := []string{"/tmp/a", "/tmp/b", "/tmp/c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilesystemPath() = %#v, want %#v", got, want)
	}

	windowsPaths, err := FilesystemPath(`C:\ProgramData\Argus\data;D:\logs\argus`)
	if err != nil {
		t.Fatalf("FilesystemPath(windows) returned error: %v", err)
	}
	wantWindows := []string{`C:\ProgramData\Argus\data`, `D:\logs\argus`}
	if !reflect.DeepEqual(windowsPaths, wantWindows) {
		t.Fatalf("FilesystemPath(windows) = %#v, want %#v", windowsPaths, wantWindows)
	}
}
