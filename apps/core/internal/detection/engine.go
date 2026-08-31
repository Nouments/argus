package detection

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Nouments/argus/apps/core/internal/alerting"
	"github.com/Nouments/argus/apps/core/internal/rules"
	"github.com/Nouments/argus/pkg/events"
)

type AlertSink interface {
	SaveAlert(context.Context, alerting.Alert) error
}

type Engine struct {
	mu      sync.Mutex
	rules   []rules.Rule
	windows map[string][]time.Time
	sink    AlertSink
	now     func() time.Time
}

func NewEngine(ruleSet []rules.Rule, sink AlertSink) (*Engine, error) {
	copied := make([]rules.Rule, len(ruleSet))
	for i, rule := range ruleSet {
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		copied[i] = rule
	}
	return &Engine{
		rules:   copied,
		windows: make(map[string][]time.Time),
		sink:    sink,
		now:     time.Now,
	}, nil
}

func (e *Engine) ProcessEvent(ctx context.Context, ev events.Event) error {
	_, err := e.Process(ctx, ev)
	return err
}

func (e *Engine) Process(ctx context.Context, ev events.Event) ([]alerting.Alert, error) {
	if e == nil {
		return nil, errors.New("detection engine is nil")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if err := ev.Validate(); err != nil {
		return nil, err
	}

	now := e.now().UTC()
	eventTime, err := time.Parse(time.RFC3339, ev.Timestamp)
	if err != nil {
		return nil, err
	}
	if eventTime.After(now) {
		eventTime = now
	}

	alerts := make([]alerting.Alert, 0)
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, rule := range e.rules {
		if !rule.Matches(ev) {
			continue
		}
		key := rule.ID + "|" + rule.GroupKey(ev)
		windowStart := eventTime.Add(-rule.Threshold.Window)
		kept := keepWithinWindow(e.windows[key], windowStart)
		kept = append(kept, eventTime)
		e.windows[key] = kept
		if len(kept) < rule.Threshold.Count {
			continue
		}
		alert := alerting.NewAlert(rule.ID, rule.Name, rule.Severity, rule.GroupKey(ev), len(kept), ev, now)
		alerts = append(alerts, alert)
		if e.sink != nil {
			if err := e.sink.SaveAlert(ctx, alert); err != nil {
				return alerts, err
			}
		}
	}
	return alerts, nil
}

func keepWithinWindow(values []time.Time, windowStart time.Time) []time.Time {
	if len(values) == 0 {
		return values
	}
	out := values[:0]
	for _, value := range values {
		if !value.Before(windowStart) {
			out = append(out, value)
		}
	}
	return out
}
