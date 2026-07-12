package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/iceq/iceq/shared/models"
)

const (
	CSRFHeaderName  = "X-IceQ-CSRF"
	CSRFHeaderValue = "1"
)

func RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) || r.Header.Get(CSRFHeaderName) == CSRFHeaderValue {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(models.ErrorResponse{
			Error: "missing CSRF header",
			Code:  "CSRF_REQUIRED",
		})
	})
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
