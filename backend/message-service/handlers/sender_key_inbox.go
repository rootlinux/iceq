package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
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

const (
	maxSenderKeyDistributionBytes  = 16 * 1024
	maxSenderKeyInboxPageItems     = 8
	maxSenderKeyInboxResponseBytes = 256 * 1024
)

const qPutSenderKeyDistribution = `
	WITH expired AS (
	  DELETE FROM sender_key_distributions
	  WHERE group_id=$1 AND recipient_uin=$3
	    AND retired_at IS NOT NULL AND retired_at < NOW()-INTERVAL '24 hours'
	), eligible AS (
	  SELECT g.id,g.crypto_epoch FROM groups g
	  WHERE g.id=$1 AND g.crypto_epoch=$4
	    AND EXISTS (SELECT 1 FROM group_members WHERE group_id=g.id AND uin=$2)
	    AND EXISTS (SELECT 1 FROM group_members WHERE group_id=g.id AND uin=$3)
	  FOR UPDATE
	), trimmed AS (
	  DELETE FROM sender_key_distributions d USING eligible e
	  WHERE NOT EXISTS (
	    SELECT 1 FROM sender_key_distributions existing
	    WHERE existing.group_id=$1 AND existing.epoch=$4 AND existing.recipient_uin=$3
	      AND existing.sender_uin=$2 AND existing.distribution_id=$5
	  ) AND
	  (d.group_id,d.epoch,d.recipient_uin,d.sender_uin,d.distribution_id) IN (
	    SELECT group_id,epoch,recipient_uin,sender_uin,distribution_id
	    FROM (
	      SELECT d2.*,ROW_NUMBER() OVER (ORDER BY created_at DESC,distribution_id DESC) AS sender_rank
	      FROM sender_key_distributions d2
	      WHERE d2.group_id=$1 AND d2.epoch=$4 AND d2.recipient_uin=$3 AND d2.sender_uin=$2
	        AND d2.retired_at IS NULL
	    ) ranked WHERE sender_rank >= ` + "4" + `
	  )
	), inserted AS (
	  INSERT INTO sender_key_distributions (group_id,epoch,recipient_uin,sender_uin,distribution_id,ciphertext,msg_type)
	  SELECT id,crypto_epoch,$3,$2,$5,$6,$7 FROM eligible
	  ON CONFLICT (group_id,epoch,recipient_uin,sender_uin,distribution_id) DO NOTHING
	  RETURNING 1
	)
	SELECT EXISTS(SELECT 1 FROM eligible),EXISTS(SELECT 1 FROM inserted)`

const qGetSenderKeyDistributions = `
	WITH expired AS (
	  DELETE FROM sender_key_distributions
	  WHERE group_id=$1 AND recipient_uin=$2
	    AND retired_at IS NOT NULL AND retired_at < NOW()-INTERVAL '24 hours'
	), ranked AS (
	  SELECT epoch,sender_uin,ciphertext,msg_type,distribution_id,retired_at,created_at,
	    ROW_NUMBER() OVER (PARTITION BY sender_uin ORDER BY epoch DESC,created_at DESC,distribution_id DESC) AS sender_rank
	  FROM sender_key_distributions
	  WHERE group_id=$1 AND recipient_uin=$2
	    AND (epoch=$3 OR retired_at > NOW()-INTERVAL '24 hours')
	)
	SELECT epoch,sender_uin,ciphertext,msg_type,distribution_id,retired_at
	FROM ranked WHERE sender_rank <= ` + "4" + `
	ORDER BY sender_rank,epoch DESC,sender_uin,created_at DESC,distribution_id DESC
	LIMIT $4 OFFSET $5`

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
		if !decodeJSON(w, r, &req, 32*1024) {
			return
		}
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(req.Ciphertext)
		if req.RecipientUIN <= 0 || req.Epoch <= 0 || req.DistributionID == "" || len(req.DistributionID) > 128 || decodeErr != nil || len(decoded) < 1 || len(decoded) > maxSenderKeyDistributionBytes || (req.MsgType != "prekey_message" && req.MsgType != "signal_message") {
			writeError(w, 422, "DISTRIBUTION_INVALID", "invalid opaque sender-key distribution")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var eligible, inserted bool
		if err := deps.PG.QueryRow(ctx, qPutSenderKeyDistribution, gid, sender, req.RecipientUIN, req.Epoch, req.DistributionID, req.Ciphertext, req.MsgType).Scan(&eligible, &inserted); err != nil {
			writeError(w, 500, "DB_ERROR", "could not persist sender-key distribution")
			return
		}
		if !eligible {
			writeError(w, 403, "GROUP_EPOCH_FORBIDDEN", "group membership or epoch is no longer current")
			return
		}
		_ = inserted // An identical distribution is an idempotent success.
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
		page := 0
		if raw := r.URL.Query().Get("page"); raw != "" {
			parsed, parseErr := strconv.Atoi(raw)
			if parseErr != nil || parsed < 0 || parsed > 10000 {
				writeError(w, 400, "PAGE_INVALID", "page must be an integer between 0 and 10000")
				return
			}
			page = parsed
		}
		rows, err := deps.PG.Query(ctx, qGetSenderKeyDistributions, gid, recipient, epoch, maxSenderKeyInboxPageItems, page*maxSenderKeyInboxPageItems)
		if err != nil {
			writeError(w, 500, "DB_ERROR", "could not read sender-key inbox")
			return
		}
		defer rows.Close()
		out := make([]senderKeyDistributionItem, 0)
		// Keep the complete JSON envelope below the cap, not merely the decoded
		// ciphertext. The fixed page size also guarantees a valid 16 KiB item
		// cannot truncate a page and make the next offset skip unseen rows.
		responseBytes := len(`{"epoch":,"distributions":[]}`) + 20
		for rows.Next() {
			var item senderKeyDistributionItem
			if rows.Scan(&item.Epoch, &item.SenderUIN, &item.Ciphertext, &item.MsgType, &item.DistributionID, &item.RetiredAt) != nil {
				writeError(w, 500, "DB_ERROR", "could not read sender-key inbox")
				return
			}
			encoded, marshalErr := json.Marshal(item)
			if marshalErr != nil {
				writeError(w, 500, "ENCODE_ERROR", "could not encode sender-key inbox")
				return
			}
			separatorBytes := 0
			if len(out) > 0 {
				separatorBytes = 1
			}
			if responseBytes+separatorBytes+len(encoded) > maxSenderKeyInboxResponseBytes {
				break
			}
			responseBytes += separatorBytes + len(encoded)
			out = append(out, item)
		}
		writeJSON(w, 200, senderKeyDistributionResponse{Epoch: epoch, Distributions: out})
	}
}
