package handlers

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordHashUsesArgon2idPHCAndVerifies(t *testing.T) {
	hash, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hashPassword() = %q, want $argon2id$ prefix", hash)
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("hashPassword() parts = %d, want 6 in PHC-like format", len(parts))
	}
	if parts[3] == "" || !strings.Contains(parts[3], "m=") || !strings.Contains(parts[3], "t=") || !strings.Contains(parts[3], "p=") {
		t.Fatalf("hashPassword() params = %q, want m/t/p params", parts[3])
	}
	if parts[4] == "" || parts[5] == "" {
		t.Fatalf("hashPassword() salt/hash must be non-empty: %q", hash)
	}

	result := verifyPassword(hash, "correct horse battery staple")
	if !result.OK {
		t.Fatal("verifyPassword() OK = false, want true")
	}
	if result.NeedsRehash {
		t.Fatal("verifyPassword() NeedsRehash = true, want false for Argon2id")
	}
}

func TestPasswordVerifyRejectsWrongPassword(t *testing.T) {
	hash, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}

	result := verifyPassword(hash, "wrong password")
	if result.OK {
		t.Fatal("verifyPassword() OK = true, want false")
	}
	if result.NeedsRehash {
		t.Fatal("verifyPassword() NeedsRehash = true, want false on mismatch")
	}
}

func TestPasswordVerifySupportsLegacyBcryptAndNeedsRehash(t *testing.T) {
	legacy, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword() error = %v", err)
	}

	result := verifyPassword(string(legacy), "correct horse battery staple")
	if !result.OK {
		t.Fatal("verifyPassword() OK = false, want true for legacy bcrypt")
	}
	if !result.NeedsRehash {
		t.Fatal("verifyPassword() NeedsRehash = false, want true for legacy bcrypt")
	}
}
