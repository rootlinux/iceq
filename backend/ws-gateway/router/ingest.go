package router

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/iceq/iceq/shared/models"
)

const durableIngestSubject = "ingest.message"

type DurableIngestRequester interface {
	Request(subject string, data []byte, timeout time.Duration) ([]byte, error)
}

func requestDurableIngest(ctx context.Context, requester DurableIngestRequester, env models.Envelope) (models.Envelope, error) {
	if requester == nil {
		return models.Envelope{}, errSendUnavailable
	}
	data, err := json.Marshal(env)
	if err != nil {
		return models.Envelope{}, errSendUnavailable
	}
	timeout := 8 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return models.Envelope{}, errSendUnavailable
	}
	reply, err := requester.Request(durableIngestSubject, data, timeout)
	if err != nil {
		return models.Envelope{}, errSendUnavailable
	}
	var ack models.Envelope
	if err := json.Unmarshal(reply, &ack); err != nil || ack.Type != models.EnvelopeTypeAck {
		return models.Envelope{}, errSendUnavailable
	}
	var payload models.AckPayload
	if err := json.Unmarshal(ack.Payload, &payload); err != nil || payload.State != models.AckStatePersisted || payload.MessageID == "" {
		return models.Envelope{}, errSendUnavailable
	}
	select {
	case <-ctx.Done():
		return models.Envelope{}, errors.Join(errSendUnavailable, ctx.Err())
	default:
		return ack, nil
	}
}
