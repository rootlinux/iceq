package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fileminio "github.com/iceq/iceq/file-service/minio"
	"github.com/iceq/iceq/shared/middleware"
)

type fakeOwners struct{ owner map[string]int64 }

func (f *fakeOwners) Register(_ context.Context, key string, uin int64) error {
	if f.owner == nil {
		f.owner = map[string]int64{}
	}
	f.owner[key] = uin
	return nil
}

type fakeSigner struct{}

func (fakeSigner) GenerateUploadURL(context.Context, fileminio.UploadRequest) (*fileminio.UploadURLResponse, error) {
	return &fileminio.UploadURLResponse{ObjectKey: "123e4567-e89b-12d3-a456-426614174000"}, nil
}
func (fakeSigner) GenerateDownloadURL(context.Context, string) (*fileminio.DownloadURLResponse, error) {
	return &fileminio.DownloadURLResponse{}, nil
}
func (fakeSigner) GenerateAvatarUploadURL(context.Context, int64) (*fileminio.UploadURLResponse, error) {
	return &fileminio.UploadURLResponse{}, nil
}
func (f *fakeOwners) Owns(_ context.Context, key string, uin int64) (bool, error) {
	return f.owner[key] == uin, nil
}

func TestObjectHandlersRejectRequestWithoutAuthenticatedActor(t *testing.T) {
	h := &Handler{}
	tests := []struct {
		name string
		body string
		fn   http.HandlerFunc
	}{
		{"upload", `{"filename":"x","content_type":"image/png","size":1}`, h.UploadURL},
		{"download", `{"object_key":"123e4567-e89b-12d3-a456-426614174000"}`, h.DownloadURL},
		{"avatar", ``, h.AvatarUploadURL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/files/"+tt.name, strings.NewReader(tt.body))
			tt.fn(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestUnrelatedUserCannotDownloadOwnersObject(t *testing.T) {
	h := &Handler{Owners: &fakeOwners{owner: map[string]int64{"123e4567-e89b-12d3-a456-426614174000": 100}}}
	req := httptest.NewRequest(http.MethodPost, "/api/files/download-url", strings.NewReader(`{"object_key":"123e4567-e89b-12d3-a456-426614174000"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 200))
	rr := httptest.NewRecorder()
	h.DownloadURL(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUploadRegistersAuthenticatedOwnerBeforeReturningURL(t *testing.T) {
	owners := &fakeOwners{}
	h := &Handler{Minio: fakeSigner{}, Owners: owners}
	req := httptest.NewRequest(http.MethodPost, "/api/files/upload-url", strings.NewReader(`{"filename":"x","content_type":"image/png","size":1}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 100))
	rr := httptest.NewRecorder()
	h.UploadURL(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if owners.owner["123e4567-e89b-12d3-a456-426614174000"] != 100 {
		t.Fatalf("owner not registered: %#v", owners.owner)
	}
}
