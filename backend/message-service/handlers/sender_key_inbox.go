package handlers

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/iceq/iceq/shared/middleware"
)

type putSenderKeyDistributionRequest struct {
	RecipientUIN   int64  `json:"recipient_uin"`
	Epoch          int64  `json:"epoch"`
	DistributionID string `json:"distribution_id"`
	Ciphertext     string `json:"ciphertext"`
	MsgType        string `json:"msg_type"`
}
type senderKeyDistributionItem struct {
	Epoch          int64      `json:"epoch"`
	SenderUIN      int64      `json:"sender_uin"`
	Ciphertext     string     `json:"ciphertext"`
	MsgType        string     `json:"msg_type"`
	DistributionID string     `json:"distribution_id"`
	RetiredAt      *time.Time `json:"retired_at,omitempty"`
}
type senderKeyDistributionResponse struct {
	Epoch         int64                       `json:"epoch"`
	Distributions []senderKeyDistributionItem `json:"distributions"`
}

const qPutSenderKeyDistribution = `
 INSERT INTO sender_key_distributions (group_id,epoch,recipient_uin,sender_uin,distribution_id,ciphertext,msg_type)
 SELECT g.id,g.crypto_epoch,$3,$2,$5,$6,$7 FROM groups g
 WHERE g.id=$1 AND g.crypto_epoch=$4
 AND EXISTS (SELECT 1 FROM group_members WHERE group_id=g.id AND uin=$2)
 AND EXISTS (SELECT 1 FROM group_members WHERE group_id=g.id AND uin=$3)
	ON CONFLICT (group_id,epoch,recipient_uin,sender_uin,distribution_id) DO NOTHING`

func NewPutSenderKeyDistributionHandler(deps GroupsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sender, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, 401, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		gid, err := parseGroupIDParam(r)
		if err != nil {
			writeError(w, 400, "GROUP_ID_INVALID", err.Error())
			return
		}
		var req putSenderKeyDistributionRequest
		if !decodeJSON(w, r, &req, 1<<20) {
			return
		}
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(req.Ciphertext)
		if req.RecipientUIN <= 0 || req.Epoch <= 0 || req.DistributionID == "" || len(req.DistributionID) > 128 || decodeErr != nil || len(decoded) < 1 || len(decoded) > 256*1024 || (req.MsgType != "prekey_message" && req.MsgType != "signal_message") {
			writeError(w, 422, "DISTRIBUTION_INVALID", "invalid opaque sender-key distribution")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		tag, err := deps.PG.Exec(ctx, qPutSenderKeyDistribution, gid, sender, req.RecipientUIN, req.Epoch, req.DistributionID, req.Ciphertext, req.MsgType)
		if err != nil {
			writeError(w, 500, "DB_ERROR", "could not persist sender-key distribution")
			return
		}
		if tag.RowsAffected() == 0 {
			writeError(w, 403, "GROUP_EPOCH_FORBIDDEN", "group membership or epoch is no longer current")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func NewGetSenderKeyDistributionsHandler(deps GroupsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		recipient, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, 401, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		gid, err := parseGroupIDParam(r)
		if err != nil {
			writeError(w, 400, "GROUP_ID_INVALID", err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var epoch int64
		if err := deps.PG.QueryRow(ctx, `SELECT g.crypto_epoch FROM groups g JOIN group_members m ON m.group_id=g.id WHERE g.id=$1 AND m.uin=$2`, gid, recipient).Scan(&epoch); err != nil {
			writeError(w, 403, "NOT_A_MEMBER", "current group membership is required")
			return
		}
		rows, err := deps.PG.Query(ctx, `SELECT epoch,sender_uin,ciphertext,msg_type,distribution_id,retired_at FROM sender_key_distributions WHERE group_id=$1 AND recipient_uin=$2 AND (epoch=$3 OR retired_at > NOW()-INTERVAL '24 hours') ORDER BY epoch DESC,sender_uin,created_at DESC LIMIT 512`, gid, recipient, epoch)
		if err != nil {
			writeError(w, 500, "DB_ERROR", "could not read sender-key inbox")
			return
		}
		defer rows.Close()
		out := make([]senderKeyDistributionItem, 0)
		for rows.Next() {
			var item senderKeyDistributionItem
			if rows.Scan(&item.Epoch, &item.SenderUIN, &item.Ciphertext, &item.MsgType, &item.DistributionID, &item.RetiredAt) != nil {
				writeError(w, 500, "DB_ERROR", "could not read sender-key inbox")
				return
			}
			out = append(out, item)
		}
		writeJSON(w, 200, senderKeyDistributionResponse{Epoch: epoch, Distributions: out})
	}
}
