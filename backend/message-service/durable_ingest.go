package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/gocql/gocql"
	"github.com/iceq/iceq/message-service/store"
	"github.com/iceq/iceq/shared/models"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const (
	durableIngestSubject = "ingest.message"
	deliveryStreamName   = "ICEQ_DELIVERY"
)

type deliveryPublisher interface {
	PublishDelivery(context.Context, string, []byte, string) error
}

type pendingOutboxReader interface {
	FetchPending(context.Context, int) ([]store.OutboxEntry, error)
}

type jetStreamDeliveryPublisher struct{ js nats.JetStreamContext }

func (p jetStreamDeliveryPublisher) PublishDelivery(ctx context.Context, subject string, body []byte, messageID string) error {
	msg := nats.NewMsg(subject)
	msg.Data = body
	msg.Header.Set(nats.MsgIdHdr, messageID)
	_, err := p.js.PublishMsg(msg, nats.Context(ctx))
	return err
}

func ensureDeliveryStream(js nats.JetStreamContext) error {
	if js == nil {
		return errors.New("jetstream unavailable")
	}
	cfg := &nats.StreamConfig{
		Name:       deliveryStreamName,
		Subjects:   []string{"msg.direct.*", "msg.group.*"},
		Storage:    nats.FileStorage,
		Retention:  nats.LimitsPolicy,
		Discard:    nats.DiscardOld,
		MaxAge:     7 * 24 * time.Hour,
		Duplicates: 24 * time.Hour,
	}
	if _, err := js.AddStream(cfg); err != nil {
		if !errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
			if _, updateErr := js.UpdateStream(cfg); updateErr != nil {
				return fmt.Errorf("ensure delivery stream: add=%v update=%w", err, updateErr)
			}
		}
	}
	_, err := js.StreamInfo(deliveryStreamName)
	return err
}

func processDurableIngest(ctx context.Context, ingester *store.DurableIngestStore, delivery deliveryPublisher, pg *pgxpool.Pool, raw []byte) (models.Envelope, error) {
	var env models.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return models.Envelope{}, err
	}
	var result store.DurableIngestResult
	var clientID, subject string
	var recipient int64
	var err error
	switch env.Type {
	case models.EnvelopeTypeDirect:
		var payload models.DirectMessagePayload
		if err = json.Unmarshal(env.Payload, &payload); err != nil || payload.SenderUIN <= 0 || payload.ReceiverUIN <= 0 || payload.ClientID == "" || len(payload.Ciphertext) == 0 || payload.Content != "" {
			return models.Envelope{}, store.ErrInvalidIngest
		}
		clientID, recipient = payload.ClientID, payload.ReceiverUIN
		subject = "msg.direct." + strconv.FormatInt(payload.ReceiverUIN, 10)
		result, err = ingester.PersistDirect(ctx, store.DurableDirectRequest{
			SenderUIN: payload.SenderUIN, ClientID: payload.ClientID, ReceiverUIN: payload.ReceiverUIN,
			ConversationID: canonicalConversationID(payload.SenderUIN, payload.ReceiverUIN), Envelope: raw, Ciphertext: payload.Ciphertext,
			MsgType: payload.MsgType, ExpiresInSeconds: payload.ExpiresInSeconds,
		})
	case models.EnvelopeTypeGroup:
		var payload models.GroupMessagePayload
		if err = json.Unmarshal(env.Payload, &payload); err != nil || payload.SenderUIN <= 0 || payload.ClientID == "" || len(payload.Ciphertext) == 0 || payload.Content != "" || payload.CryptoEpoch <= 0 {
			return models.Envelope{}, store.ErrInvalidIngest
		}
		groupID, parseErr := gocql.ParseUUID(payload.GroupID)
		if parseErr != nil || pg == nil || authorizeGroupMessageEpoch(ctx, pg, payload.GroupID, payload.SenderUIN, payload.CryptoEpoch) != nil {
			return models.Envelope{}, errors.New("group authorization failed")
		}
		clientID, subject = payload.ClientID, "msg.group."+payload.GroupID
		result, err = ingester.PersistGroup(ctx, store.DurableGroupRequest{SenderUIN: payload.SenderUIN, ClientID: payload.ClientID, GroupID: groupID, CryptoEpoch: payload.CryptoEpoch, Envelope: raw, Ciphertext: payload.Ciphertext, MsgType: payload.MsgType, ExpiresInSeconds: payload.ExpiresInSeconds})
	default:
		return models.Envelope{}, errors.New("unsupported durable ingest type")
	}
	if err != nil {
		return models.Envelope{}, err
	}
	if result.State == store.IngestStored {
		deliveryEnv := models.Envelope{Type: env.Type, ID: result.MessageID.String(), TS: result.CreatedAt.UnixMilli(), Payload: env.Payload}
		body, marshalErr := json.Marshal(deliveryEnv)
		if marshalErr == nil {
			publishCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			publishErr := delivery.PublishDelivery(publishCtx, subject, body, result.MessageID.String())
			cancel()
			if publishErr == nil {
				// The durable key is authenticated sender plus client id; recover
				// sender from the receipt-independent envelope payload.
				var sender struct {
					SenderUIN int64 `json:"sender_uin"`
				}
				_ = json.Unmarshal(env.Payload, &sender)
				_ = ingester.MarkDelivered(ctx, store.IngestKey{SenderUIN: sender.SenderUIN, ClientID: clientID}, result.MessageID)
			}
		}
	}
	return models.NewEnvelope(models.EnvelopeTypeAck, models.AckPayload{MessageID: clientID, State: models.AckStatePersisted, RecipientUIN: recipient})
}

func deliverOutboxEntry(ctx context.Context, ingester *store.DurableIngestStore, delivery deliveryPublisher, entry store.OutboxEntry) error {
	var env models.Envelope
	if err := json.Unmarshal(entry.Envelope, &env); err != nil {
		return err
	}
	env.ID, env.TS = entry.MessageID.String(), entry.CreatedAt.UnixMilli()
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	var subject string
	switch entry.Kind {
	case store.IngestKindDirect:
		subject = "msg.direct." + strconv.FormatInt(entry.ReceiverUIN, 10)
	case store.IngestKindGroup:
		subject = "msg.group." + entry.GroupID.String()
	default:
		return errors.New("unknown outbox message kind")
	}
	if err := delivery.PublishDelivery(ctx, subject, body, entry.MessageID.String()); err != nil {
		return err
	}
	return ingester.MarkDelivered(ctx, entry.Key, entry.MessageID)
}

func drainPendingOutbox(ctx context.Context, reader pendingOutboxReader, ingester *store.DurableIngestStore, delivery deliveryPublisher) {
	entries, err := reader.FetchPending(ctx, 100)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		_ = deliverOutboxEntry(ctx, ingester, delivery, entry)
	}
}

func runOutboxWorker(ctx context.Context, reader pendingOutboxReader, ingester *store.DurableIngestStore, delivery deliveryPublisher) {
	drainPendingOutbox(ctx, reader, ingester, delivery)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			drainPendingOutbox(ctx, reader, ingester, delivery)
		}
	}
}
