package models

import (
	"errors"
	"testing"
)

func TestLoginRequestValidate_AllowsUsernameWithoutEmail(t *testing.T) {
	req := LoginRequest{
		Username: "alice_1",
		Password: "correct-horse",
	}

	if err := req.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestLoginRequestValidate_RejectsMissingIdentifier(t *testing.T) {
	req := LoginRequest{
		Password: "correct-horse",
	}

	err := req.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want non-nil")
	}
	if !errors.Is(err, ErrLoginIdentifierMissing) {
		t.Fatalf("Validate() error = %v, want ErrLoginIdentifierMissing", err)
	}
}
