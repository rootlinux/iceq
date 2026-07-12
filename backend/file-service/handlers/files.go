// Package handlers wires the file-service's HTTP routes to
// the minio wrapper. The split is one-to-one with the
// REST surface:
//
//	POST /api/files/upload-url        → UploadURL
//	POST /api/files/download-url      → DownloadURL
//	POST /api/files/avatar-upload-url → AvatarUploadURL
//	GET  /health                      → health (mounted in main.go)
//
// Every route under /api/files/* requires a verified
// access-token JWT. The auth middleware (in
// file-service/middleware) injects the caller's UIN into
// the request context; the handlers read it back with
// middleware.GetUIN. We never read a client-claimed UIN —
// the server-side fill is the only trustworthy source.
//
// Privacy:
//   - Original filenames are not echoed in responses,
//     persisted in logs, or included in object keys
//     (the minio wrapper drops them).
//   - Object keys ARE returned in responses (the
//     caller needs them to download), but they are
//     random UUIDs for files and "avatars/<uin>"
//     for avatars — both safe to log at the caller's
//     discretion.
//   - Error responses use a static (code, message)
//     shape and never include caller-supplied data.
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"

	"github.com/iceq/iceq/file-service/minio"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/iceq/iceq/shared/models"
)

// ----------------------------------------------------------------------------
// Public handler type.
// ----------------------------------------------------------------------------

// Handler carries the dependencies the route handlers
// need. Constructed once in main.go and passed by value
// to the route registrations.
type Handler struct {
	Minio *minio.MinioClient
}

// New is a thin constructor so main.go doesn't have to
// name the struct literal inline.
func New(m *minio.MinioClient) *Handler {
	return &Handler{Minio: m}
}

// ----------------------------------------------------------------------------
// Request / response wire types.
//
// The request bodies are tiny (filename/content_type/size
// for upload, just object_key for download). Defining
// them inline keeps the JSON tags next to the handler
// that uses them, and avoids a wire-types.go file that
// exists only to declare three-field structs.
// ----------------------------------------------------------------------------

type uploadURLRequest struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
}

type downloadURLRequest struct {
	ObjectKey string `json:"object_key"`
}

// objectKeyPattern is the allowlist for /download-url
// input. Two checks in one: it must look like a UUID
// (the only shape we issue for files), AND it must
// contain no path-traversal characters (the only
// separator that could appear in a UUID is "-").
//
// The simpler alternative (just check for "/" or "..")
// would let through a maliciously-crafted "uuid/../foo"
// which, when concatenated with the bucket path, escapes
// the bucket's namespace. The regex is the strict version
// of "is this a UUID?".
var objectKeyPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ----------------------------------------------------------------------------
// POST /api/files/upload-url
// ----------------------------------------------------------------------------

// UploadURL mints a pre-signed PUT URL for the
// private files bucket. The body carries the
// client-declared (filename, content_type, size)
// triple; the original filename is dropped on the
// floor by the minio wrapper, the content type is
// checked against the allowlist, and the size is
// range-checked.
//
// Status codes:
//   200 — success
//   400 — body malformed
//   401 — auth (handled by middleware)
//   413 — size out of range
//   415 — content type not on the allowlist
//   500 — MinIO unreachable / presign failed
func (h *Handler) UploadURL(w http.ResponseWriter, r *http.Request) {
	var req uploadURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", "request body is not valid JSON")
		return
	}

	resp, err := h.Minio.GenerateUploadURL(r.Context(), minio.UploadRequest{
		Filename:    req.Filename,
		ContentType: req.ContentType,
		Size:        req.Size,
	})
	if err != nil {
		switch {
		case errors.Is(err, minio.ErrSizeExceeded):
			// 413 is the spec's choice for "file too
			// large" — it matches the convention
			// nginx uses for the same condition.
			writeError(w, http.StatusRequestEntityTooLarge, "SIZE_OUT_OF_RANGE", "file size must be > 0 and <= 100MB")
			return
		case errors.Is(err, minio.ErrContentTypeNotAllowed):
			// 415 is the spec's choice for
			// "unsupported media type" — matches
			// the convention from RFC 7231.
			writeError(w, http.StatusUnsupportedMediaType, "CONTENT_TYPE_NOT_ALLOWED", "content type is not on the upload allowlist")
			return
		}
		// Anything else is a MinIO-level failure.
		// We log the error code (opaque to caller)
		// but do not include caller-supplied
		// data in the response.
		log.Printf("[file-service] presign upload: %v", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate upload URL")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// ----------------------------------------------------------------------------
// POST /api/files/download-url
// ----------------------------------------------------------------------------

// DownloadURL mints a pre-signed GET URL for an
// existing object in the private files bucket.
//
// The object_key is validated against the UUID
// regex before it is handed to MinIO. This is
// path-traversal defense: even if the MinIO SDK
// were permissive about "../" in object keys
// (it isn't, by default), the regex blocks it
// before the request leaves our process.
//
// Status codes:
//   200 — success
//   400 — body malformed or object_key not a UUID
//   401 — auth (handled by middleware)
//   500 — MinIO unreachable / presign failed
func (h *Handler) DownloadURL(w http.ResponseWriter, r *http.Request) {
	var req downloadURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", "request body is not valid JSON")
		return
	}
	if !objectKeyPattern.MatchString(req.ObjectKey) {
		// Reject anything that isn't a UUID —
		// this is the path-traversal defense
		// described in the doc comment.
		writeError(w, http.StatusBadRequest, "INVALID_OBJECT_KEY", "object_key must be a UUID")
		return
	}

	resp, err := h.Minio.GenerateDownloadURL(r.Context(), req.ObjectKey)
	if err != nil {
		log.Printf("[file-service] presign download: %v", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate download URL")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// ----------------------------------------------------------------------------
// POST /api/files/avatar-upload-url
// ----------------------------------------------------------------------------

// AvatarUploadURL mints a pre-signed PUT URL for the
// user's avatar. The UIN is taken from the verified
// JWT, never from the request body — a tampered
// client cannot upload an avatar to another user's
// namespace.
//
// Status codes:
//   200 — success
//   401 — auth (handled by middleware; the missing
//         UIN case is also a 401 because it should
//         not happen behind the auth gate)
//   500 — MinIO unreachable / presign failed
func (h *Handler) AvatarUploadURL(w http.ResponseWriter, r *http.Request) {
	uin, ok := middleware.GetUIN(r.Context())
	if !ok || uin <= 0 {
		// Defense-in-depth: the auth middleware
		// should always inject a UIN. If it
		// didn't, the request reached us without
		// going through the gate — refuse.
		writeError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "missing or invalid uin in context")
		return
	}

	resp, err := h.Minio.GenerateAvatarUploadURL(r.Context(), uin)
	if err != nil {
		log.Printf("[file-service] presign avatar: %v", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate avatar upload URL")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// ----------------------------------------------------------------------------
// JSON helpers. Local to this package so the handler
// file is the only place in the service that writes
// JSON bodies — same pattern as message-service.
// ----------------------------------------------------------------------------

// writeJSON marshals v to w with the given status code.
// Marshal errors are logged but cannot be reported to
// the client (the response is already half-written).
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[file-service] marshal response: %v", err)
	}
}

// writeError writes the standard error body. The
// (code, message) pair is static — caller-supplied
// data is never included in error responses, so a
// malicious client can't smuggle log-injection
// payloads through a 4xx path.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, models.ErrorResponse{Error: message, Code: code})
}
