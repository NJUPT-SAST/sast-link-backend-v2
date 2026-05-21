package infra

import (
	"context"
	"log/slog"
	"testing"
)

func TestInitLogger_Levels(t *testing.T) {
	cases := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"WARN", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"", slog.LevelInfo},
		{"unknown", slog.LevelInfo},
	}

	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			logger := InitLogger(c.input)
			if logger == nil {
				t.Fatal("InitLogger returned nil")
			}
			if !logger.Enabled(context.Background(), c.want) {
				t.Errorf("level %q not enabled", c.input)
			}
		})
	}
}
