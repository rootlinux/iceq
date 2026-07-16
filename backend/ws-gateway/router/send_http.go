package router

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/iceq/iceq/shared/models"
	"github.com/iceq/iceq/ws-gateway/client"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EnvelopePublisher interface{ Publish(string, []byte) error }
type GroupSendAuthorizer interface {
	IsCurrentMember(context.Context, string, int64, int64) (bool, error)
}
type SendDeps struct {
	Publisher EnvelopePublisher
	Deduper   client.MessageDeduper
	Groups    GroupSendAuthorizer
}

func NewSendHandler(deps SendDeps) http.Handler {
	if deps.Publisher == nil || deps.Deduper == nil {
		panic("send dependencies are incomplete")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		actor, ok := middleware.GetUIN(r.Context())
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		var env models.Envelope
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&env); err != nil {
			http.Error(w, "invalid envelope", http.StatusBadRequest)
			return
		}
		ack, err := processHTTPSend(r.Context(), actor, env, deps)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errSendUnavailable) {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, err.Error(), status)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(ack)
	})
}

var errSendUnavailable = errors.New("send unavailable")

func processHTTPSend(ctx context.Context, actor int64, env models.Envelope, deps SendDeps) (models.Envelope, error) {
	serverID := uuid.NewString()
	ts := time.Now().UTC().Truncate(time.Minute).UnixMilli()
	var clientID, subject string
	var recipient int64
	var payload any
	switch env.Type {
	case models.EnvelopeTypeDirect:
		p, err := parseDirectPayload(env.Payload)
		if err != nil {
			return models.Envelope{}, err
		}
		// HTTP fallback is E2EE-only; it never accepts legacy plaintext.
		if len(p.Ciphertext) == 0 || p.Content != "" {
			return models.Envelope{}, errors.New("opaque ciphertext is required")
		}
		p.SenderUIN = actor
		if err := authorizeDirectConversation(p, actor); err != nil {
			return models.Envelope{}, err
		}
		if err := validateDirectPayload(p); err != nil {
			return models.Envelope{}, err
		}
		clientID = p.ClientID
		recipient = p.ReceiverUIN
		subject = "msg.direct." + itoa(recipient)
		payload = forwardDirectPayload(p, actor)
	case models.EnvelopeTypeGroup:
		p, err := parseGroupPayload(env.Payload)
		if err != nil {
			return models.Envelope{}, err
		}
		if err := validateGroupPayload(p); err != nil {
			return models.Envelope{}, err
		}
		if deps.Groups == nil {
			return models.Envelope{}, errSendUnavailable
		}
		member, err := deps.Groups.IsCurrentMember(ctx, p.GroupID, actor, p.CryptoEpoch)
		if err != nil {
			return models.Envelope{}, errSendUnavailable
		}
		if !member {
			return models.Envelope{}, errors.New("sender is not a current group member")
		}
		p.SenderUIN = actor
		clientID = p.ClientID
		subject = "msg.group." + p.GroupID
		payload = p
	default:
		return models.Envelope{}, errors.New("unsupported envelope type")
	}
	prior, duplicate, err := reserveMessageID(ctx, deps.Deduper, actor, clientID, serverID)
	if err != nil {
		return models.Envelope{}, errSendUnavailable
	}
	if duplicate {
		serverID = prior
	} else {
		out := models.Envelope{Type: env.Type, ID: serverID, TS: ts, Payload: mustMarshalRaw(payload)}
		data, err := json.Marshal(out)
		if err != nil {
			_ = deps.Deduper.Release(ctx, actor, clientID, serverID)
			return models.Envelope{}, errSendUnavailable
		}
		if err := deps.Publisher.Publish(subject, data); err != nil {
			_ = deps.Deduper.Release(ctx, actor, clientID, serverID)
			return models.Envelope{}, errSendUnavailable
		}
	}
	return models.NewEnvelope(models.EnvelopeTypeAck, models.AckPayload{MessageID: ackMessageID(serverID, clientID), State: models.AckStatePersisted, RecipientUIN: recipient})
}

type PGGroupSendAuthorizer struct{ pg *pgxpool.Pool }

func NewPGGroupSendAuthorizer(pg *pgxpool.Pool) *PGGroupSendAuthorizer {
	if pg == nil {
		panic("group pg is nil")
	}
	return &PGGroupSendAuthorizer{pg: pg}
}
func (a *PGGroupSendAuthorizer) IsCurrentMember(ctx context.Context, groupID string, actor, epoch int64) (bool, error) {
	var one int
	err := a.pg.QueryRow(ctx, `SELECT 1 FROM group_members m JOIN groups g ON g.id=m.group_id WHERE m.group_id=$1 AND m.uin=$2 AND g.crypto_epoch=$3`, groupID, actor, epoch).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
