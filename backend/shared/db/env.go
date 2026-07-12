package db

import (
	"os"
	"strconv"
)

// envOr returns the value of the named environment variable, or
// `fallback` if the variable is unset or empty. Centralized so the
// three factories in this package share an identical read pattern
// and the same "empty string counts as unset" semantics — the latter
// matters because shell-style `export FOO=` lines produce an empty
// (but set) variable that we want to treat as missing.
func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}

// envIntOr returns the named environment variable parsed as an int,
// or `fallback` if the variable is unset, empty, or not a valid int.
// Parsing errors fall through to the default silently; we do not
// want a malformed env var to crash the service at boot.
func envIntOr(name string, fallback int) int {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
