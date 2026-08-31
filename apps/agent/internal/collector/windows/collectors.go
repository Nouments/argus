package windows

import (
	"github.com/Nouments/argus/apps/agent/internal/collector"
	"github.com/Nouments/argus/apps/agent/internal/collector/windows/network"
	"github.com/Nouments/argus/apps/agent/internal/collector/windows/process"
	"github.com/Nouments/argus/apps/agent/internal/collector/windows/eventlog"
	"github.com/Nouments/argus/apps/agent/internal/collector/windows/etw"
)

func NewNetworkCollector() collector.Collector  { return network.NewNetworkCollector() }
func NewProcessCollector() collector.Collector  { return process.NewProcessCollector() }
func NewEventLogCollector() collector.Collector { return eventlog.NewEventLogCollector() }
func NewETWCollector() collector.Collector     { return etw.NewETWCollector() }
