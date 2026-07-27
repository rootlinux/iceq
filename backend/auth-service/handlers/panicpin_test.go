package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iceq/iceq/shared/middleware"
)

func TestSetPanicPinHandlerRequiresAuth(t *testing.T) {
	handler := NewSetPanicPinHandler(SetPanicPinDeps{
		LookupPasswordHash: func(context.Context, int64) (string, error) { t.Fatal("should not be called"); return "", nil },
	})
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-pin", strings.NewReader(`{"current_password":"x","pin":"1234"}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestSetPanicPinHandlerRejectsWrongCurrentPasswordWithoutWriting(t *testing.T) {
	correctHash, err := hashPassword("correct-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	setCalled := false
	handler := NewSetPanicPinHandler(SetPanicPinDeps{
		LookupPasswordHash: func(context.Context, int64) (string, error) { return correctHash, nil },
		SetPin:             func(context.Context, int64, string) error { setCalled = true; return nil },
	})
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-pin", strings.NewReader(`{"current_password":"wrong-password","pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
	if setCalled {
		t.Fatal("SetPin was called despite a wrong current password")
	}
}

func TestSetPanicPinHandlerRejectsNonFourDigitPins(t *testing.T) {
	correctHash, err := hashPassword("correct-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	for _, badPin := range []string{"123", "12345", "abcd", "12a4", "-123", " 123"} {
		setCalled := false
		handler := NewSetPanicPinHandler(SetPanicPinDeps{
			LookupPasswordHash: func(context.Context, int64) (string, error) { return correctHash, nil },
			SetPin:             func(context.Context, int64, string) error { setCalled = true; return nil },
		})
		req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-pin", strings.NewReader(`{"current_password":"correct-password","pin":"`+badPin+`"}`))
		req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("pin=%q status = %d, want 400", badPin, rr.Code)
		}
		if setCalled {
			t.Fatalf("pin=%q: SetPin was called for an invalid pin", badPin)
		}
	}
}

func TestSetPanicPinHandlerStoresAHashNotThePlaintextPin(t *testing.T) {
	correctHash, err := hashPassword("correct-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	var storedUIN int64
	var storedHash string
	handler := NewSetPanicPinHandler(SetPanicPinDeps{
		LookupPasswordHash: func(context.Context, int64) (string, error) { return correctHash, nil },
		SetPin: func(_ context.Context, uin int64, hash string) error {
			storedUIN, storedHash = uin, hash
			return nil
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-pin", strings.NewReader(`{"current_password":"correct-password","pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000042))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}
	if storedUIN != 10000042 {
		t.Fatalf("uin = %d, want 10000042", storedUIN)
	}
	if storedHash == "1234" || storedHash == "" {
		t.Fatalf("stored value %q is not a hash", storedHash)
	}
	if !verifyPassword(storedHash, "1234").OK {
		t.Fatal("stored hash does not verify against the pin that was set")
	}
}

func TestSetPanicPinHandlerEmptyPinClearsIt(t *testing.T) {
	correctHash, err := hashPassword("correct-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	var clearedWith *string
	handler := NewSetPanicPinHandler(SetPanicPinDeps{
		LookupPasswordHash: func(context.Context, int64) (string, error) { return correctHash, nil },
		SetPin: func(_ context.Context, _ int64, hash string) error {
			clearedWith = &hash
			return nil
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-pin", strings.NewReader(`{"current_password":"correct-password","pin":""}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}
	if clearedWith == nil || *clearedWith != "" {
		t.Fatalf("SetPin called with %v, want empty string (clear)", clearedWith)
	}
}

func TestSetPanicPinHandlerSurfacesStorageFailure(t *testing.T) {
	correctHash, err := hashPassword("correct-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	handler := NewSetPanicPinHandler(SetPanicPinDeps{
		LookupPasswordHash: func(context.Context, int64) (string, error) { return correctHash, nil },
		SetPin:             func(context.Context, int64, string) error { return errors.New("db unavailable") },
	})
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-pin", strings.NewReader(`{"current_password":"correct-password","pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}
