package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iceq/iceq/key-service/models"
	"github.com/iceq/iceq/shared/middleware"
)

type recordingKeyStore struct {
	upsertUIN int64
	addUIN    int64
	countUIN  int64
}

func (s *recordingKeyStore) GetBundle(context.Context, int64) (models.BundleResponse, error) {
	return models.BundleResponse{}, nil
}
func (s *recordingKeyStore) UpsertBundle(_ context.Context, uin int64, _ string, _ models.SignedPrekey, _ int) error {
	s.upsertUIN = uin
	return nil
}
func (s *recordingKeyStore) AddOneTimePrekeys(_ context.Context, uin int64, _ []models.OneTimePrekey) error {
	s.addUIN = uin
	return nil
}
func (s *recordingKeyStore) CountUnusedPrekeys(_ context.Context, uin int64) (int, error) {
	s.countUIN = uin
	return 7, nil
}

func TestPrivateKeyHandlersRejectRequestWithoutAuthenticatedActor(t *testing.T) {
	tests := []struct {
		name string
		body string
		fn   http.HandlerFunc
	}{
		{"bundle", `{}`, NewPostBundleHandler(BundleDeps{}, nil)},
		{"prekeys", `{}`, NewAddPrekeysHandler(PrekeyDeps{})},
		{"count", ``, NewCountPrekeysHandler(PrekeyDeps{})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/keys/"+tt.name, strings.NewReader(tt.body))
			tt.fn(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestPrivateKeyWritesAndCountAreScopedToAuthenticatedActor(t *testing.T) {
	const actor = int64(101)
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	store := &recordingKeyStore{}

	bundleBody := fmt.Sprintf(`{"identity_key":%q,"signed_pre_key":{"id":1,"public_key":%q,"signature":%q},"registration_id":1,"one_time_pre_keys":[{"id":2,"public_key":%q}]}`, key, key, base64.RawURLEncoding.EncodeToString(make([]byte, 64)), key)
	bundleBody = strings.ReplaceAll(bundleBody, `\"`, `"`)
	req := httptest.NewRequest(http.MethodPost, "/api/keys/bundle", strings.NewReader(bundleBody))
	req = req.WithContext(middleware.WithUIN(req.Context(), actor))
	rr := httptest.NewRecorder()
	NewPostBundleHandler(BundleDeps{Keystore: store}, func(context.Context, int64) (string, error) { return key, nil })(rr, req)
	if rr.Code != http.StatusNoContent || store.upsertUIN != actor || store.addUIN != actor {
		t.Fatalf("bundle status=%d upsert=%d add=%d body=%s", rr.Code, store.upsertUIN, store.addUIN, rr.Body.String())
	}

	prekeyBody := fmt.Sprintf(`{"prekeys":[{"id":3,"public_key":%q}]}`, key)
	prekeyBody = strings.ReplaceAll(prekeyBody, `\"`, `"`)
	req = httptest.NewRequest(http.MethodPost, "/api/keys/prekeys", strings.NewReader(prekeyBody))
	req = req.WithContext(middleware.WithUIN(req.Context(), actor))
	rr = httptest.NewRecorder()
	NewAddPrekeysHandler(PrekeyDeps{Keystore: store})(rr, req)
	if rr.Code != http.StatusNoContent || store.addUIN != actor {
		t.Fatalf("prekeys status=%d add=%d body=%s", rr.Code, store.addUIN, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/keys/prekeys/count?uin=202", nil)
	req = req.WithContext(middleware.WithUIN(req.Context(), actor))
	rr = httptest.NewRecorder()
	NewCountPrekeysHandler(PrekeyDeps{Keystore: store})(rr, req)
	if rr.Code != http.StatusOK || store.countUIN != actor || !strings.Contains(rr.Body.String(), `"count":7`) {
		t.Fatalf("count status=%d uin=%d body=%s", rr.Code, store.countUIN, rr.Body.String())
	}
}
