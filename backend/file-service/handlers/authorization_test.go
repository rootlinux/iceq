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

type fakeOwners struct {
	owner  map[string]int64
	grants map[string]map[int64]bool
}

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
	return f.owner[key] == uin || (f.grants[key] != nil && f.grants[key][uin]), nil
}
func (f *fakeOwners) Grant(_ context.Context, key string, owner, grantee int64) (bool, error) {
	if f.owner[key] != owner {
		return false, nil
	}
	if f.grants == nil {
		f.grants = map[string]map[int64]bool{}
	}
	if f.grants[key] == nil {
		f.grants[key] = map[int64]bool{}
	}
	f.grants[key][grantee] = true
	return true, nil
}
func (f *fakeOwners) Revoke(_ context.Context, key string, owner, grantee int64) (bool, error) {
	if f.owner[key] != owner {
		return false, nil
	}
	delete(f.grants[key], grantee)
	return true, nil
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

func TestOwnerCanGrantAndRevokeRecipientDownload(t *testing.T) {
	key := "123e4567-e89b-12d3-a456-426614174000"
	owners := &fakeOwners{owner: map[string]int64{key: 100}}
	h := &Handler{Minio: fakeSigner{}, Owners: owners}
	grantReq := httptest.NewRequest(http.MethodPost, "/api/files/grants", strings.NewReader(`{"object_key":"`+key+`","grantee_uin":200}`))
	grantReq = grantReq.WithContext(middleware.WithUIN(grantReq.Context(), 100))
	grantRR := httptest.NewRecorder()
	h.Grant(grantRR, grantReq)
	if grantRR.Code != http.StatusNoContent {
		t.Fatalf("grant status=%d body=%s", grantRR.Code, grantRR.Body.String())
	}
	downloadReq := httptest.NewRequest(http.MethodPost, "/api/files/download-url", strings.NewReader(`{"object_key":"`+key+`"}`))
	downloadReq = downloadReq.WithContext(middleware.WithUIN(downloadReq.Context(), 200))
	downloadRR := httptest.NewRecorder()
	h.DownloadURL(downloadRR, downloadReq)
	if downloadRR.Code != http.StatusOK {
		t.Fatalf("grantee download status=%d body=%s", downloadRR.Code, downloadRR.Body.String())
	}
	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/files/grants", strings.NewReader(`{"object_key":"`+key+`","grantee_uin":200}`))
	revokeReq = revokeReq.WithContext(middleware.WithUIN(revokeReq.Context(), 100))
	revokeRR := httptest.NewRecorder()
	h.RevokeGrant(revokeRR, revokeReq)
	if revokeRR.Code != http.StatusNoContent {
		t.Fatalf("revoke status=%d", revokeRR.Code)
	}
}

func TestUnrelatedUserCannotGrantOwnersObject(t *testing.T) {
	key := "123e4567-e89b-12d3-a456-426614174000"
	owners := &fakeOwners{owner: map[string]int64{key: 100}}
	h := &Handler{Owners: owners}
	req := httptest.NewRequest(http.MethodPost, "/api/files/grants", strings.NewReader(`{"object_key":"`+key+`","grantee_uin":300}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 200))
	rr := httptest.NewRecorder()
	h.Grant(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestForeignActorCannotRevokeGrantAndGrantRemains(t *testing.T) {
	key := "123e4567-e89b-12d3-a456-426614174000"
	owners := &fakeOwners{owner: map[string]int64{key: 100}, grants: map[string]map[int64]bool{key: {200: true}}}
	h := &Handler{Minio: fakeSigner{}, Owners: owners}
	req := httptest.NewRequest(http.MethodDelete, "/api/files/grants", strings.NewReader(`{"object_key":"`+key+`","grantee_uin":200}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 300))
	rr := httptest.NewRecorder()
	h.RevokeGrant(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !owners.grants[key][200] {
		t.Fatal("foreign revoke removed grant")
	}
}
