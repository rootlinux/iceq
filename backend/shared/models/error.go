package models

// ErrorResponse is the canonical wire-format error body used by
// every IceQ HTTP service. Centralized here so middleware and
// handlers can both produce the same shape without depending on
// any single service's `models` package.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}
