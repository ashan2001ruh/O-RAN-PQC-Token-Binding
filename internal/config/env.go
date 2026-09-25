// Package config reads component configuration from environment variables,
// collecting every problem so a misconfigured pod reports all of them at once.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Env accumulates parse errors while reading variables.
type Env struct {
	errs []error
}

func (e *Env) lookup(key string) (string, bool) {
	v, ok := os.LookupEnv(key)
	v = strings.TrimSpace(v)
	return v, ok && v != ""
}

// Str returns the variable or def when unset.
func (e *Env) Str(key, def string) string {
	if v, ok := e.lookup(key); ok {
		return v
	}
	return def
}

// Req returns the variable and records an error when it is unset.
func (e *Env) Req(key string) string {
	v, ok := e.lookup(key)
	if !ok {
		e.errs = append(e.errs, fmt.Errorf("%s is required", key))
	}
	return v
}

// Dur parses a Go duration (e.g. 15m, 168h).
func (e *Env) Dur(key string, def time.Duration) time.Duration {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", key, err))
		return def
	}
	return d
}

// Int parses a decimal integer.
func (e *Env) Int(key string, def int) int {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", key, err))
		return def
	}
	return n
}

// Bool parses true/false/1/0.
func (e *Env) Bool(key string, def bool) bool {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", key, err))
		return def
	}
	return b
}

// List splits a comma-separated variable, dropping empty items.
func (e *Env) List(key string, def []string) []string {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// Fail records a validation error discovered by the caller.
func (e *Env) Fail(format string, args ...any) {
	e.errs = append(e.errs, fmt.Errorf(format, args...))
}

// Err returns all accumulated errors, or nil.
func (e *Env) Err() error {
	return errors.Join(e.errs...)
}
