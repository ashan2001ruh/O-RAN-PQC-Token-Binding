// Package logx builds the structured (JSON) logger used by every component.
package logx

import (
	"log/slog"
	"os"
	"strings"
)

// New returns a JSON logger tagged with the component name. LOG_LEVEL selects the level.
func New(component string) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(h).With("component", component)
}
