package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/iceq/iceq/shared/models"
	"github.com/iceq/iceq/ws-gateway/router"
	"github.com/nats-io/nats.go"
)

const (
	deliveryStreamName      = "ICEQ_DELIVERY"
	deliveryConsumerDurable = "ICEQ_GATEWAY_DELIVERY"
	deliveryReceiptSubject  = "delivery.accepted"
)

type recipientAccepter interface {
	Accept(context.Context, router.RecipientAcceptance) (bool, error)
	ReadAcceptedAfter(context.Context, router.RecipientAcceptanceScope, string, int64) ([]router.AcceptedEnvelope, error)
}
type liveDeliveryNotifier interface{ SendLive(int64, []byte) }
type deliveryReceiptRequester interface {
	Request(string, []byte, time.Duration) ([]byte, error)
}
type deliveryReceipt struct {
	SenderUIN int64  `json:"sender_uin"`
	ClientID  string `json:"client_id"`
	MessageID string `json:"message_id"`
}

func replayAccepted(ctx context.Context, queue recipientAccepter, live liveDeliveryNotifier, recipientUIN int64) error {
	scope, err := router.DirectRecipientScope(recipientUIN)
	if err != nil {
		return err
	}
	items, err := queue.ReadAcceptedAfter(ctx, scope, "", 1000)
	if err != nil {
		return err
	}
	for _, item := range items {
		live.SendLive(recipientUIN, item.Envelope)
	}
	return nil
}

func acceptDelivery(ctx context.Context, accepter recipientAccepter, live liveDeliveryNotifier, receipts deliveryReceiptRequester, subject string, body []byte) error {
	var env models.Envelope
	if err := json.Unmarshal(body, &env); err != nil || env.ID == "" {
		return errors.New("invalid delivery envelope")
	}
	var sender int64
	var clientID string
	var recipients []int64
	var scopes []router.RecipientAcceptanceScope
	var expiresAt *time.Time
	switch env.Type {
	case models.EnvelopeTypeDirect:
		var payload models.DirectMessagePayload
		if err := json.Unmarshal(env.Payload, &payload); err != nil || payload.SenderUIN <= 0 || payload.ReceiverUIN <= 0 || payload.ClientID == "" {
			return errors.New("invalid direct delivery")
		}
		if subject != "msg.direct."+fmt.Sprint(payload.ReceiverUIN) {
			return errors.New("direct subject mismatch")
		}
		scope, err := router.DirectRecipientScope(payload.ReceiverUIN)
		if err != nil {
			return err
		}
		sender, clientID, recipients, scopes = payload.SenderUIN, payload.ClientID, []int64{payload.ReceiverUIN}, []router.RecipientAcceptanceScope{scope}
		if payload.ExpiresInSeconds > 0 {
			expiry := time.UnixMilli(env.TS).Add(time.Duration(payload.ExpiresInSeconds) * time.Second)
			expiresAt = &expiry
		}
	case models.EnvelopeTypeGroup:
		var payload models.GroupMessagePayload
		if err := json.Unmarshal(env.Payload, &payload); err != nil || payload.SenderUIN <= 0 || payload.GroupID == "" || payload.ClientID == "" {
			return errors.New("invalid group delivery")
		}
		if subject != "msg.group."+payload.GroupID || len(payload.RecipientUINs) == 0 {
			return errors.New("group subject mismatch")
		}
		sender, clientID, recipients = payload.SenderUIN, payload.ClientID, payload.RecipientUINs
		for _, uin := range payload.RecipientUINs {
			scope, err := router.GroupMemberScope(payload.GroupID, uin)
			if err != nil {
				return err
			}
			scopes = append(scopes, scope)
		}
		if payload.ExpiresInSeconds > 0 {
			expiry := time.UnixMilli(env.TS).Add(time.Duration(payload.ExpiresInSeconds) * time.Second)
			expiresAt = &expiry
		}
	default:
		return errors.New("unsupported delivery type")
	}
	for i, scope := range scopes {
		_, err := accepter.Accept(ctx, router.RecipientAcceptance{Scope: scope, MessageID: env.ID, Envelope: body, ExpiresAt: expiresAt})
		if err != nil {
			return err
		}
		// Delivery is always replayed from the durable recipient queue. This
		// also repairs a crash between Accept and the prior wake-up attempt.
		if err := replayAccepted(ctx, accepter, live, recipients[i]); err != nil {
			return err
		}
	}
	receiptBody, _ := json.Marshal(deliveryReceipt{SenderUIN: sender, ClientID: clientID, MessageID: env.ID})
	if _, err := receipts.Request(deliveryReceiptSubject, receiptBody, 3*time.Second); err != nil {
		return err
	}
	return nil
}

func ensureDeliveryConsumer(js nats.JetStreamContext) error {
	if js == nil {
		return errors.New("jetstream unavailable")
	}
	cfg := &nats.ConsumerConfig{Durable: deliveryConsumerDurable, AckPolicy: nats.AckExplicitPolicy, AckWait: 30 * time.Second, MaxAckPending: 256, FilterSubject: "msg.>"}
	if _, err := js.AddConsumer(deliveryStreamName, cfg); err != nil {
		info, infoErr := js.ConsumerInfo(deliveryStreamName, deliveryConsumerDurable)
		if infoErr != nil {
			return fmt.Errorf("ensure durable delivery consumer: %w", err)
		}
		if info.Config.AckPolicy != nats.AckExplicitPolicy || info.Config.FilterSubject != "msg.>" {
			return errors.New("durable delivery consumer has incompatible configuration")
		}
	}
	return nil
}

func startDeliveryConsumer(ctx context.Context, js nats.JetStreamContext, accepter recipientAccepter, live liveDeliveryNotifier, receipts deliveryReceiptRequester) error {
	if err := ensureDeliveryConsumer(js); err != nil {
		return err
	}
	sub, err := js.PullSubscribe("msg.>", deliveryConsumerDurable, nats.Bind(deliveryStreamName, deliveryConsumerDurable))
	if err != nil {
		return err
	}
	go func() {
		for ctx.Err() == nil {
			msgs, err := sub.Fetch(16, nats.MaxWait(time.Second))
			if err != nil && !errors.Is(err, nats.ErrTimeout) {
				continue
			}
			for _, msg := range msgs {
				entryCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				err := acceptDelivery(entryCtx, accepter, live, receipts, msg.Subject, msg.Data)
				cancel()
				if err != nil {
					_ = msg.NakWithDelay(time.Second)
					continue
				}
				_ = msg.AckSync()
			}
		}
	}()
	return nil
}
