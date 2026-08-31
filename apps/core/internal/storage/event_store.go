package storage

import (
	"context"

	"github.com/Nouments/argus/pkg/events"
)

type EventStore interface {
	SaveEvent(context.Context, events.Event) error
}
