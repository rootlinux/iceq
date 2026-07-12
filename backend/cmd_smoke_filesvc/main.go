// file-service smoke test.
//
// Exercises the 8 verification steps from the Step 7 spec:
//
//  1. POST /api/files/upload-url       → presigned PUT URL
//  2. PUT file directly to MinIO       → bytes land
//  3. POST /api/files/download-url     → presigned GET URL
//  4. GET file via presigned GET URL   → bytes match
//  5. POST /api/files/avatar-upload-url → avatar presigned URL
//  6. object_key contains no UIN (files), contains uin (avatars)
//  7. oversized file (>100MB) returns 413
//  8. disallowed content type returns 415
//
// Run from inside the iceq-net network with the same
// ICEQ_JWT_SECRET as the auth-service / file-service:
//
//	docker run --rm --network iceq-net \
//	  -v /path/to/iceq:/src \
//	  -w /src/backend -e ICEQ_JWT_SECRET=dev-secret-not-for-prod \
//	  alpine:3.20 /src/backend/cmd_smoke_filesvc/smoke
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/iceq/iceq/shared/jwt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const (
	filesvcBase  = "http://file-service:8080"
	defaultPGDSN = "postgres://postgres:postgres@postgres:5432/iceq?sslmode=disable"
	// F-2 (JWT assessment): 38 bytes, above the
	// minSecretBytes=32 floor.
	jwtSecret = "filesvc-smoketest-secret-not-for-prod-32"

	// 1 MB - small for the happy-path PUT.
	smallBody = "iceq-smoke-test-1mb-encrypted-blob-aaaaaaaaaaaaaaaaaaaaaaa"

	// 100 MB + 1 byte - used to verify the 413 path.
	oversizeBodySize = 100*1024*1024 + 1
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const uin int64 = 9999001
	mgr := newJWTManager()
	access := mintAccessToken(mgr, uin)

	// ---- 1. POST /api/files/upload-url → presigned PUT URL ----
	fmt.Println("[smoke] ==== 1. POST /api/files/upload-url ====")
	uploadResp := postUploadURL(ctx, access, "secret-document.pdf", "application/pdf", int64(len(smallBody)))
	fmt.Printf("[smoke] OK object_key=%s expires_at=%s\n", uploadResp.ObjectKey, uploadResp.ExpiresAt)
	if uploadResp.ObjectKey == "" {
		fail("object_key is empty")
	}
	if !strings.HasPrefix(uploadResp.UploadURL, "http://minio:9000/iceq-files/") {
		fail(fmt.Sprintf("upload_url has unexpected host/path: %s", uploadResp.UploadURL[:min(80, len(uploadResp.UploadURL))]))
	}
	objectKey := uploadResp.ObjectKey

	// ---- 2. PUT file directly to MinIO via presigned URL ----
	fmt.Println("[smoke] ==== 2. PUT file to MinIO via presigned URL ====")
	putBytes(ctx, uploadResp.UploadURL, []byte(smallBody), "application/pdf")
	fmt.Println("[smoke] OK PUT returned 200")

	// ---- 3. POST /api/files/download-url → presigned GET URL ----
	fmt.Println("[smoke] ==== 3. POST /api/files/download-url ====")
	downloadResp := postDownloadURL(ctx, access, objectKey)
	fmt.Printf("[smoke] OK download_url=%s expires_at=%s\n", downloadResp.DownloadURL[:min(60, len(downloadResp.DownloadURL))], downloadResp.ExpiresAt)
	if !strings.HasPrefix(downloadResp.DownloadURL, "http://minio:9000/iceq-files/") {
		fail("download_url has unexpected host")
	}

	// ---- 4. GET file via presigned URL → verify bytes match ----
	fmt.Println("[smoke] ==== 4. GET file via presigned URL ====")
	got := getBytes(ctx, downloadResp.DownloadURL)
	if string(got) != smallBody {
		fail(fmt.Sprintf("downloaded bytes do not match: got %d bytes, want %d", len(got), len(smallBody)))
	}
	fmt.Printf("[smoke] OK downloaded %d bytes match uploaded %d bytes\n", len(got), len(smallBody))

	// ---- 5. POST /api/files/avatar-upload-url → avatar presigned URL ----
	fmt.Println("[smoke] ==== 5. POST /api/files/avatar-upload-url ====")
	avatarResp := postAvatarUploadURL(ctx, access)
	fmt.Printf("[smoke] OK avatar object_key=%s\n", avatarResp.ObjectKey)

	// ---- 6. object_key: no UIN (files), contains uin (avatars) ----
	fmt.Println("[smoke] ==== 6. object_key privacy check ====")
	// Files: should be a UUID with no slash and no uin substring.
	if strings.Contains(objectKey, "/") {
		fail("file object_key contains a slash: " + objectKey)
	}
	if strings.Contains(objectKey, strconv.FormatInt(uin, 10)) {
		fail("file object_key contains the test uin: " + objectKey)
	}
	// Avatars: should be exactly "avatars/<uin>".
	wantAvatarKey := "avatars/" + strconv.FormatInt(uin, 10)
	if avatarResp.ObjectKey != wantAvatarKey {
		fail(fmt.Sprintf("avatar object_key = %q, want %q", avatarResp.ObjectKey, wantAvatarKey))
	}
	fmt.Printf("[smoke] OK file object_key=%q (no uin, no slash) avatar object_key=%q (contains uin)\n", objectKey, avatarResp.ObjectKey)

	// ---- 7. oversized file (>100MB) returns 413 ----
	fmt.Println("[smoke] ==== 7. oversize file returns 413 ====")
	status, body := postUploadURLStatus(ctx, access, "huge.bin", "application/octet-stream", oversizeBodySize)
	if status != http.StatusRequestEntityTooLarge {
		fail(fmt.Sprintf("oversize upload-url: status=%d (want 413), body=%s", status, body))
	}
	fmt.Printf("[smoke] OK oversize returned 413 with body=%s\n", body)

	// ---- 8. disallowed content type returns 415 ----
	fmt.Println("[smoke] ==== 8. disallowed content type returns 415 ====")
	status, body = postUploadURLStatus(ctx, access, "evil.exe", "application/x-msdownload", 1024)
	if status != http.StatusUnsupportedMediaType {
		fail(fmt.Sprintf("disallowed content type: status=%d (want 415), body=%s", status, body))
	}
	fmt.Printf("[smoke] OK disallowed content type returned 415 with body=%s\n", body)

	fmt.Println("[smoke] SMOKE TEST OK")
}

// ----------------------------------------------------------------------------
// Wire types. The file-service uses minified JSON tags so we
// match them exactly here.
// ----------------------------------------------------------------------------

type uploadURLResp struct {
	ObjectKey string    `json:"object_key"`
	UploadURL string    `json:"upload_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

type downloadURLResp struct {
	ObjectKey   string    `json:"object_key"`
	DownloadURL string    `json:"download_url"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ----------------------------------------------------------------------------
// HTTP helpers.
// ----------------------------------------------------------------------------

func postUploadURL(ctx context.Context, access, filename, ct string, size int64) uploadURLResp {
	status, body := postUploadURLStatus(ctx, access, filename, ct, size)
	if status != http.StatusOK {
		fail(fmt.Sprintf("POST upload-url: status=%d body=%s", status, body))
	}
	var out uploadURLResp
	mustJSON([]byte(body), &out)
	return out
}

func postUploadURLStatus(ctx context.Context, access, filename, ct string, size int64) (int, string) {
	body, _ := json.Marshal(map[string]any{
		"filename":     filename,
		"content_type": ct,
		"size":         size,
	})
	req, _ := http.NewRequestWithContext(ctx, "POST", filesvcBase+"/api/files/upload-url", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("POST upload-url: " + err.Error())
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody)
}

func postDownloadURL(ctx context.Context, access, objectKey string) downloadURLResp {
	body, _ := json.Marshal(map[string]any{
		"object_key": objectKey,
	})
	req, _ := http.NewRequestWithContext(ctx, "POST", filesvcBase+"/api/files/download-url", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("POST download-url: " + err.Error())
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fail(fmt.Sprintf("POST download-url: status=%d body=%s", resp.StatusCode, string(respBody)))
	}
	var out downloadURLResp
	mustJSON(respBody, &out)
	return out
}

func postAvatarUploadURL(ctx context.Context, access string) uploadURLResp {
	req, _ := http.NewRequestWithContext(ctx, "POST", filesvcBase+"/api/files/avatar-upload-url", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("POST avatar-upload-url: " + err.Error())
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fail(fmt.Sprintf("POST avatar-upload-url: status=%d body=%s", resp.StatusCode, string(respBody)))
	}
	var out uploadURLResp
	mustJSON(respBody, &out)
	return out
}

func putBytes(ctx context.Context, presignedURL string, body []byte, contentType string) {
	// We have to parse the URL and use the raw
	// host:port so the request goes to the MinIO
	// service inside the iceq-net network. The
	// presigned URL already has the right path +
	// query string.
	u, err := url.Parse(presignedURL)
	if err != nil {
		fail("parse presigned URL: " + err.Error())
	}
	// Rewrite scheme to http (MinIO is on plain
	// HTTP inside the docker network).
	u.Scheme = "http"
	req, _ := http.NewRequestWithContext(ctx, "PUT", u.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("PUT to MinIO: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		fail(fmt.Sprintf("PUT to MinIO: status=%d body=%s", resp.StatusCode, string(respBody)))
	}
}

func getBytes(ctx context.Context, presignedURL string) []byte {
	u, err := url.Parse(presignedURL)
	if err != nil {
		fail("parse presigned URL: " + err.Error())
	}
	u.Scheme = "http"
	req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("GET from MinIO: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		fail(fmt.Sprintf("GET from MinIO: status=%d body=%s", resp.StatusCode, string(respBody)))
	}
	body, _ := io.ReadAll(resp.Body)
	return body
}

// ----------------------------------------------------------------------------
// JWT helpers.
// ----------------------------------------------------------------------------

func newJWTManager() *jwt.Manager {
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379"})
	// F-5: NewManager requires a *pgxpool.Pool for the
	// session_epoch check. The smoke test only signs
	// tokens, so the pool is never actually queried —
	// but the constructor still needs the handle.
	pool, err := pgxpool.New(context.Background(), pgDSNFromEnv())
	if err != nil {
		must(err, "pgxpool.New")
	}
	defer pool.Close()
	secret := os.Getenv("ICEQ_JWT_SECRET")
	if secret == "" {
		secret = jwtSecret
	}
	mgr, err := jwt.NewManager(secret, rdb, pool)
	must(err, "jwt.NewManager")
	return mgr
}

func mintAccessToken(mgr *jwt.Manager, uin int64) string {
	res, err := mgr.Sign(uin, jwt.TokenTypeAccess)
	must(err, "jwt.Sign")
	return res.Token
}

func mustJSON(body []byte, v any) {
	if err := json.Unmarshal(body, v); err != nil {
		fail(fmt.Sprintf("decode response: %v body=%s", err, string(body)))
	}
}

func must(err error, label string) {
	if err != nil {
		fail(label + ": " + err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "[smoke] FAIL:", msg)
	os.Exit(1)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func pgDSNFromEnv() string {
	if dsn := os.Getenv("ICEQ_PG_DSN"); dsn != "" {
		return dsn
	}
	if password := os.Getenv("POSTGRES_PASSWORD"); password != "" {
		return "postgres://postgres:" + password + "@postgres:5432/iceq?sslmode=disable"
	}
	return defaultPGDSN
}
