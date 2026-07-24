package minio

import (
	"net/url"
	"strings"
	"testing"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestToProxyPathRewritesInternalHostToRelativePath(t *testing.T) {
	// This is exactly the shape minio-go returns when the client was
	// constructed with the internal ICEQ_MINIO_ENDPOINT (default
	// "minio:9000") — a Docker-network-only hostname no browser, over
	// Tor or otherwise, can resolve or reach.
	signed := mustParseURL(t, "http://minio:9000/iceq-files/abc-123?X-Amz-Signature=deadbeef&X-Amz-Expires=300")

	got := toProxyPath(signed)

	want := "/files-proxy/iceq-files/abc-123?X-Amz-Signature=deadbeef&X-Amz-Expires=300"
	if got != want {
		t.Fatalf("toProxyPath = %q, want %q", got, want)
	}
}

func TestToProxyPathHandlesAvatarBucketPath(t *testing.T) {
	signed := mustParseURL(t, "http://minio:9000/iceq-avatars/avatars/10000001?X-Amz-Signature=cafef00d")

	got := toProxyPath(signed)

	want := "/files-proxy/iceq-avatars/avatars/10000001?X-Amz-Signature=cafef00d"
	if got != want {
		t.Fatalf("toProxyPath = %q, want %q", got, want)
	}
}

func TestToProxyPathHandlesNoQueryString(t *testing.T) {
	signed := mustParseURL(t, "http://minio:9000/iceq-files/abc-123")

	got := toProxyPath(signed)

	want := "/files-proxy/iceq-files/abc-123"
	if got != want {
		t.Fatalf("toProxyPath = %q, want %q", got, want)
	}
}

func TestToProxyPathNeverLeaksTheInternalHostname(t *testing.T) {
	signed := mustParseURL(t, "http://minio:9000/iceq-files/abc-123?X-Amz-Signature=x")

	got := toProxyPath(signed)

	if strings.Contains(got, "minio:9000") {
		t.Fatalf("toProxyPath leaked the internal hostname: %q", got)
	}
	if !strings.HasPrefix(got, "/") {
		t.Fatalf("toProxyPath must return a same-origin relative path starting with '/', got %q", got)
	}
}
