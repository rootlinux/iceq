// edge-identity is a private, no-log trust-boundary service. Caddy alone sends
// it a raw network address; it returns only short-lived opaque HMAC identities.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	edgeClientIPHeader = "X-IceQ-Edge-Client-IP"
	identityHeader     = "X-IceQ-RateLimit-Identity"
)

type config struct {
	current  []byte
	previous []byte
	now      func() time.Time
}

func loadConfig() (config, error) {
	c := config{current: []byte(os.Getenv("ICEQ_EDGE_IDENTITY_HMAC_SECRET")), previous: []byte(os.Getenv("ICEQ_EDGE_IDENTITY_HMAC_PREVIOUS_SECRET")), now: time.Now}
	if len(c.current) < 32 {
		return config{}, errors.New("current edge identity secret must be at least 32 bytes")
	}
	if len(c.previous) > 0 && len(c.previous) < 32 {
		return config{}, errors.New("previous edge identity secret must be empty or at least 32 bytes")
	}
	if len(c.previous) > 0 && hmac.Equal(c.current, c.previous) {
		return config{}, errors.New("current and previous edge identity secrets must differ")
	}
	return c, nil
}

func signIdentity(secret []byte, ip string, now time.Time) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("iceq-edge-identity\x00" + now.UTC().Format("2006-01-02") + "\x00" + ip))
	keyHash := sha256.Sum256(secret)
	return "v1." + hex.EncodeToString(keyHash[:6]) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func newHandler(cfg config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /identity", func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(r.Header.Get(edgeClientIPHeader))
		ip := net.ParseIP(raw)
		if ip == nil || strings.ContainsAny(raw, ",:") && ip.To4() != nil {
			http.Error(w, "invalid edge identity input", http.StatusBadRequest)
			return
		}
		canonical := ip.String()
		w.Header().Add(identityHeader, signIdentity(cfg.current, canonical, cfg.now()))
		if len(cfg.previous) > 0 {
			w.Header().Add(identityHeader, signIdentity(cfg.previous, canonical, cfg.now()))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func newServer(cfg config, errorOutput io.Writer) *http.Server {
	if errorOutput == nil {
		errorOutput = io.Discard
	}
	return &http.Server{
		Addr:              ":8090",
		Handler:           newHandler(cfg),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    4096,
		ErrorLog:          log.New(errorOutput, "", 0),
	}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "-healthcheck" {
		client := http.Client{Timeout: time.Second}
		resp, err := client.Get("http://127.0.0.1:8090/health")
		if err != nil || resp.StatusCode != http.StatusNoContent {
			os.Exit(1)
		}
		_ = resp.Body.Close()
		return
	}
	cfg, err := loadConfig()
	if err != nil {
		os.Exit(1)
	}
	if err := newServer(cfg, io.Discard).ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		os.Exit(1)
	}
}
