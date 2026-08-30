package host

import (
	"net"
	"os"
	"runtime"
)

// host spec that  will bw returned to the main on boot for checking os to load path
type Host struct {
	OS   string
	Arch string
}

// metadata that is used  for endpoint spec on dashboard or the tui on server
type HostMetadata struct {
	Hostname   string
	Interfaces []net.Interface
}

// detect os on boot
func DetectkHost() (*Host, error) {
	return &Host{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}, nil
}

// fetch metadata for enrollement
func GetMetadata() (*HostMetadata, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	return &HostMetadata{
		Hostname:   hostname,
		Interfaces: interfaces,
	}, nil

}
