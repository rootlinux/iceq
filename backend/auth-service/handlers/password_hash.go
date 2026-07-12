package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	// bcryptCost remains the legacy bcrypt work factor used for
	// timing masks and any remaining bcrypt-only compatibility paths.
	bcryptCost = 12

	argon2idMemory      uint32 = 64 * 1024
	argon2idIterations  uint32 = 3
	argon2idParallelism uint8  = 4
	argon2idSaltLength         = 16
	argon2idKeyLength          = 32
)

var passwordHashEncoding = base64.RawStdEncoding

type passwordVerifyResult struct {
	OK          bool
	NeedsRehash bool
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, argon2idSaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("password hash: salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		argon2idIterations,
		argon2idMemory,
		argon2idParallelism,
		argon2idKeyLength,
	)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2idMemory,
		argon2idIterations,
		argon2idParallelism,
		passwordHashEncoding.EncodeToString(salt),
		passwordHashEncoding.EncodeToString(hash),
	), nil
}

func verifyPassword(storedHash, password string) passwordVerifyResult {
	if strings.HasPrefix(storedHash, "$argon2id$") {
		return verifyArgon2idPassword(storedHash, password)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)); err == nil {
		return passwordVerifyResult{OK: true, NeedsRehash: true}
	}
	return passwordVerifyResult{}
}

func verifyArgon2idPassword(storedHash, password string) passwordVerifyResult {
	params, salt, expected, ok := parseArgon2idHash(storedHash)
	if !ok {
		return passwordVerifyResult{}
	}

	actual := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		uint32(len(expected)),
	)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return passwordVerifyResult{}
	}
	return passwordVerifyResult{OK: true}
}

type argon2idParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

func parseArgon2idHash(storedHash string) (argon2idParams, []byte, []byte, bool) {
	parts := strings.Split(storedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argon2idParams{}, nil, nil, false
	}
	if parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return argon2idParams{}, nil, nil, false
	}

	params, ok := parseArgon2idParams(parts[3])
	if !ok {
		return argon2idParams{}, nil, nil, false
	}
	salt, err := passwordHashEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return argon2idParams{}, nil, nil, false
	}
	hash, err := passwordHashEncoding.DecodeString(parts[5])
	if err != nil || len(hash) == 0 {
		return argon2idParams{}, nil, nil, false
	}

	return params, salt, hash, true
}

func parseArgon2idParams(raw string) (argon2idParams, bool) {
	values := map[string]uint64{}
	for _, part := range strings.Split(raw, ",") {
		key, value, found := strings.Cut(part, "=")
		if !found {
			return argon2idParams{}, false
		}
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil || parsed == 0 {
			return argon2idParams{}, false
		}
		values[key] = parsed
	}

	memory, hasMemory := values["m"]
	iterations, hasIterations := values["t"]
	parallelism, hasParallelism := values["p"]
	if !hasMemory || !hasIterations || !hasParallelism || parallelism > 255 {
		return argon2idParams{}, false
	}

	return argon2idParams{
		memory:      uint32(memory),
		iterations:  uint32(iterations),
		parallelism: uint8(parallelism),
	}, true
}
