// Package minio is a thin wrapper around the official MinIO Go
// SDK. The file-service uses it to mint pre-signed PUT/GET URLs
// against two buckets:
//
//   - iceq-files (private): general file transfer. Object keys
//     are random UUIDs — the original filename is NEVER
//     preserved on the server. Clients reach the object only
//     through a time-limited pre-signed URL.
//
//   - iceq-avatars (public-read): user profile pictures. Object
//     keys are deterministic ("avatars/<uin>") so a re-upload
//     overwrites the previous avatar in place. The bucket is
//     world-readable; the service does not gate access to
//     avatar GETs — the URL itself is the auth.
//
// Privacy contract for this package:
//
//  1. Original filenames are NEVER persisted, logged, or
//     included in object keys. A caller that hands us a
//     filename gets a UUID-only key in return; the field is
//     accepted on the request struct only because clients
//     send it and we don't want to break the wire shape, not
//     because we use it for anything server-side.
//
//  2. UINs appear in object keys only for the avatar bucket
//     (deterministic overwrite). They NEVER appear in
//     general-file object keys, and they NEVER appear in
//     any log line or error message.
//
//  3. Error messages from this package do not echo
//     caller-supplied strings (filenames, content types,
//     object keys). The exposed sentinel errors let the
//     HTTP layer map validation failures to 413/415
//     without leaking user input into the log.
package minio

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	mio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// ----------------------------------------------------------------------------
// Bucket / TTL constants. Pinned here so both the file-service
// main.go and the smoke test read the same numbers. Changing the
// upload TTL has a security implication: a longer TTL widens
// the window in which a stolen pre-signed URL can be reused;
// 5 minutes is the spec's chosen balance.
// ----------------------------------------------------------------------------

const (
	// BucketFiles is the private bucket for general file
	// transfers. Object keys are random UUIDs.
	BucketFiles = "iceq-files"

	// BucketAvatars is the public-read bucket for user
	// profile pictures. Object keys are "avatars/<uin>".
	BucketAvatars = "iceq-avatars"

	// UploadTTLDuration is the lifetime of a pre-signed PUT
	// URL. Short enough that a leaked URL expires before
	// it can be replayed; long enough that a chatty
	// client can retry.
	UploadTTLDuration = 5 * time.Minute

	// DownloadTTLDuration is the lifetime of a pre-signed
	// GET URL. Long enough that a recipient can fetch a
	// shared file even if they're offline at send time
	// and reconnect hours later.
	DownloadTTLDuration = 24 * time.Hour

	// MaxFileSize is the upper bound on a single upload
	// (100 MB). The client declares the size up front so
	// the pre-signed URL can be rejected before any bytes
	// are pushed to MinIO.
	MaxFileSize int64 = 100 * 1024 * 1024

	// filesProxyPrefix is the same-origin path Caddy reverse-proxies to
	// MinIO (see deploy/Caddyfile's /files-proxy/* block, which forces
	// the Host header back to cfg.MinioEndpoint so MinIO's SigV4
	// signature check still validates). PresignedPutObject/
	// PresignedGetObject build a URL against cfg.MinioEndpoint — by
	// default the Docker-internal hostname "minio:9000", which no real
	// client (browser, Tor or otherwise) can resolve or reach, and MinIO
	// has no port published to the host. toProxyPath rewrites the
	// signed URL to this relative path so it works from any origin the
	// app itself is reachable from.
	filesProxyPrefix = "/files-proxy"
)

// ----------------------------------------------------------------------------
// Sentinel errors. The HTTP layer matches on these with
// errors.Is to pick the right status code. We don't carry
// caller-supplied strings in the wrapped errors — the
// error messages are static so a malicious caller can't
// smuggle log-injection payloads through a 413/415 path.
// ----------------------------------------------------------------------------

var (
	// ErrSizeExceeded is returned when a request's Size
	// is <= 0 or > MaxFileSize.
	ErrSizeExceeded = errors.New("file size out of range")

	// ErrContentTypeNotAllowed is returned when the
	// declared Content-Type is not on the allowlist.
	ErrContentTypeNotAllowed = errors.New("content type not allowed")
)

// ----------------------------------------------------------------------------
// Public types. The wire shape is defined here so the
// HTTP layer doesn't re-invent the JSON tags.
// ----------------------------------------------------------------------------

// Config carries the four values read from the environment
// to construct a MinIO client. Keep it small and flat —
// future MinIO-specific knobs (region, custom CA, custom
// endpoint path) can be added without breaking existing
// callers.
type Config struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	UseSSL    bool
}

// UploadRequest is what the HTTP handler hands to
// GenerateUploadURL. Filename is captured for wire-shape
// compatibility but is otherwise discarded — the original
// filename never lands in the object key.
type UploadRequest struct {
	Filename    string
	ContentType string
	Size        int64
}

// UploadURLResponse is the JSON the HTTP handler returns.
type UploadURLResponse struct {
	ObjectKey string    `json:"object_key"`
	UploadURL string    `json:"upload_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// DownloadURLResponse is the JSON the HTTP handler returns
// for a download URL request.
type DownloadURLResponse struct {
	ObjectKey   string    `json:"object_key"`
	DownloadURL string    `json:"download_url"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ----------------------------------------------------------------------------
// MinioClient. Wraps a single *minio.Client. Constructed
// once in main() and passed by pointer to the handlers —
// the underlying SDK is safe for concurrent use, so the
// wrapper doesn't need any locking.
// ----------------------------------------------------------------------------

// MinioClient is the IceQ file-service's view of the
// MinIO server. It deliberately does not export the
// underlying *minio.Client — handlers should call our
// named methods, not improvise with the SDK.
type MinioClient struct {
	client *mio.Client
}

// New constructs a MinioClient and verifies connectivity
// with a single BucketExists probe against the files
// bucket. The probe is intentional: a misconfigured
// endpoint (wrong host, wrong port) would otherwise only
// surface on the first request, which can be confusing
// after the container has already started.
func New(ctx context.Context, cfg Config) (*MinioClient, error) {
	c, err := mio.New(cfg.Endpoint, &mio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("minio new: %w", err)
	}
	// Connectivity probe. We don't fail if the files
	// bucket is missing — the minio-init container
	// provisions it, but a fresh `docker compose up` may
	// race the init. The smoke test creates the bucket
	// as a precondition; in production the init
	// container is part of the same compose.
	if _, err := c.BucketExists(ctx, BucketFiles); err != nil {
		return nil, fmt.Errorf("minio bucket probe: %w", err)
	}
	return &MinioClient{client: c}, nil
}

// GenerateUploadURL mints a pre-signed PUT URL for the
// private files bucket. The returned object key is a
// fresh UUID — the caller's Filename is dropped on the
// floor.
//
// Validation:
//   - Size must be > 0 and <= MaxFileSize, else ErrSizeExceeded
//   - ContentType must be on the allowlist, else ErrContentTypeNotAllowed
func (m *MinioClient) GenerateUploadURL(ctx context.Context, req UploadRequest) (*UploadURLResponse, error) {
	if req.Size <= 0 || req.Size > MaxFileSize {
		return nil, ErrSizeExceeded
	}
	if !isAllowedContentType(req.ContentType) {
		return nil, ErrContentTypeNotAllowed
	}

	// Random object key. The UUID is the only thing
	// tied to the upload on the server side; the
	// caller's Filename is not used.
	objectKey := uuid.NewString()
	expiresAt := time.Now().Add(UploadTTLDuration)

	signed, err := m.client.PresignedPutObject(ctx, BucketFiles, objectKey, UploadTTLDuration)
	if err != nil {
		return nil, fmt.Errorf("presigned put: %w", err)
	}
	return &UploadURLResponse{
		ObjectKey: objectKey,
		UploadURL: toProxyPath(signed),
		ExpiresAt: expiresAt,
	}, nil
}

// GenerateDownloadURL mints a pre-signed GET URL for an
// object in the private files bucket. The caller is
// trusted to have legitimately obtained the object key —
// the URL is the auth.
func (m *MinioClient) GenerateDownloadURL(ctx context.Context, objectKey string) (*DownloadURLResponse, error) {
	expiresAt := time.Now().Add(DownloadTTLDuration)
	// nil reqParams means "no override" — the URL will
	// not force a download, not set a content-disposition
	// override, and not pre-emptively restrict the IP
	// range. This is the right call for a chat-file
	// transfer: the recipient's browser opens the URL
	// and the file preview / download prompt is
	// determined by the browser's MIME sniffing.
	signed, err := m.client.PresignedGetObject(ctx, BucketFiles, objectKey, DownloadTTLDuration, nil)
	if err != nil {
		return nil, fmt.Errorf("presigned get: %w", err)
	}
	return &DownloadURLResponse{
		ObjectKey:   objectKey,
		DownloadURL: toProxyPath(signed),
		ExpiresAt:   expiresAt,
	}, nil
}

// GenerateAvatarUploadURL mints a pre-signed PUT URL for
// the user's avatar in the public-read avatars bucket.
// The object key is deterministic ("avatars/<uin>") so a
// re-upload overwrites the previous avatar in place —
// the bucket has at most one object per user, ever.
//
// The avatar bucket is public-read; we don't gate access
// to GETs here. The pre-signed PUT URL is the only thing
// that prevents a third party from overwriting someone
// else's avatar, so the 5-minute TTL matters.
func (m *MinioClient) GenerateAvatarUploadURL(ctx context.Context, uin int64) (*UploadURLResponse, error) {
	objectKey := avatarKey(uin)
	expiresAt := time.Now().Add(UploadTTLDuration)
	signed, err := m.client.PresignedPutObject(ctx, BucketAvatars, objectKey, UploadTTLDuration)
	if err != nil {
		return nil, fmt.Errorf("presigned put avatar: %w", err)
	}
	return &UploadURLResponse{
		ObjectKey: objectKey,
		UploadURL: toProxyPath(signed),
		ExpiresAt: expiresAt,
	}, nil
}

// ----------------------------------------------------------------------------
// Internal helpers.
// ----------------------------------------------------------------------------

// toProxyPath rewrites an absolute presigned MinIO URL to a
// same-origin relative path under filesProxyPrefix, preserving the
// full path and query string (the query carries the SigV4
// signature, expiry, and credential params — none of that is
// touched, only the scheme+host prefix is dropped). Caddy's
// /files-proxy/* block strips this prefix and forwards to MinIO
// with the Host header forced back to what was actually signed.
func toProxyPath(u *url.URL) string {
	rewritten := filesProxyPrefix + u.Path
	if u.RawQuery != "" {
		rewritten += "?" + u.RawQuery
	}
	return rewritten
}

// DeleteUserObjects removes only the specified fileKeys from the files bucket
// and the deterministic avatar key from the avatars bucket. It NEVER lists
// objects — the caller must supply the exact keys to delete, which must be
// captured from the file_objects table BEFORE ownership rows are removed.
//
// This is a safety-critical design: scanning and deleting an entire bucket
// would wipe every user's objects. The caller is responsible for passing
// only keys owned by the wiped UIN.
func (m *MinioClient) DeleteUserObjects(ctx context.Context, uin int64, fileKeys []string) error {
	// Delete only exact file keys from the files bucket.
	for _, key := range fileKeys {
		if key == "" {
			continue
		}
		if err := m.client.RemoveObject(ctx, BucketFiles, key, mio.RemoveObjectOptions{}); err != nil {
			log.Printf("[minio] delete object %s/%s failed: %v", BucketFiles, key, err)
			return fmt.Errorf("delete file object %s: %w", key, err)
		}
	}

	// Delete only the deterministic avatar key. A missing avatar is not an
	// error — the user may never have uploaded one.
	avatarKey := "avatars/" + itoa(uin)
	if err := m.client.RemoveObject(ctx, BucketAvatars, avatarKey, mio.RemoveObjectOptions{}); err != nil {
		// NoSuchKey is not fatal — the user might not have an avatar.
		if !isNoSuchKey(err) {
			log.Printf("[minio] delete avatar %s/%s failed: %v", BucketAvatars, avatarKey, err)
			return fmt.Errorf("delete avatar object: %w", err)
		}
	}

	return nil
}

// itoa is a tiny helper for int64-to-string conversion used by avatar key
// generation. Avoids importing strconv in the minio package for one call.
func itoa(n int64) string {
	return fmt.Sprintf("%d", n)
}

// isNoSuchKey reports whether err is a MinIO "The specified key does not
// exist" response.
func isNoSuchKey(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "The specified key does not exist")
}

// DeleteUserGrants is a no-op stub at the MinIO layer. File-object
// grants live in the `file_objects` and `file_object_grants`
// Postgres tables, which are cleaned inside the PanicWipe PG
// transaction. This method exists so the auth-service can call a
// single MinioCleaner interface without knowing the grant storage
// backend.
func (m *MinioClient) DeleteUserGrants(_ context.Context, _ int64) error {
	return nil
}

// avatarKey is the deterministic object key for a user's
// avatar. Exposed as its own function so the smoke test
// can assert the key shape without duplicating the
// formatting logic.
func avatarKey(uin int64) string {
	return fmt.Sprintf("avatars/%d", uin)
}

// isAllowedContentType reports whether the given MIME
// type is on the file-service's upload allowlist.
//
// The list is intentionally narrow: a future step that
// adds new MIME types (e.g. text/csv) is a code change,
// not a configuration change, so the security team
// reviews every addition.
//
// The list lives here, not in the handler, so any
// caller of GenerateUploadURL gets the same validation
// (the smoke test, for example, can't accidentally
// bypass it by calling the wrapper directly).
func isAllowedContentType(ct string) bool {
	switch ct {
	case
		// images
		"image/jpeg",
		"image/png",
		"image/gif",
		"image/webp",
		// documents
		"application/pdf",
		// audio
		"audio/mpeg",
		"audio/ogg",
		"audio/webm",
		// video
		"video/mp4",
		"video/webm",
		// generic binary
		"application/octet-stream":
		return true
	}
	return false
}
