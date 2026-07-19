package main

import (
	"net/url"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
)

func TestRunRejectsUnconfirmedProductionUpBeforeConnecting(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_USER", "sastlink")
	t.Setenv("DB_PASSWORD", "not-used")
	t.Setenv("DB_NAME", "sastlink")

	err := run([]string{"up"})
	if err == nil || !strings.Contains(err.Error(), "requires --confirm-production") {
		t.Fatalf("run(up) error = %v, want production confirmation error", err)
	}
}

func TestParseCommandRejectsEmptyArguments(t *testing.T) {
	_, err := parseCommand(nil)
	if err == nil {
		t.Fatal("parseCommand(nil) error = nil, want usage error")
	}
}

func TestParseCommandRejectsUnconfirmedForce(t *testing.T) {
	_, err := parseCommand([]string{"force", "1"})
	if err == nil {
		t.Fatal("parseCommand(force 1) error = nil, want confirmation error")
	}
}

func TestParseCommandAcceptsConfirmedV1Baseline(t *testing.T) {
	command, err := parseCommand([]string{"force", "1", "--confirm-existing-baseline"})
	if err != nil {
		t.Fatalf("parseCommand() error = %v", err)
	}
	if command.kind != commandForceV1 {
		t.Fatalf("kind = %v, want %v", command.kind, commandForceV1)
	}
}

func TestParseCommandAcceptsOnlyExplicitCommands(t *testing.T) {
	tests := []struct {
		name string
		args []string
		kind commandKind
	}{
		{name: "up", args: []string{"up"}, kind: commandUp},
		{name: "confirmed production up", args: []string{"up", "--confirm-production"}, kind: commandUp},
		{name: "version", args: []string{"version"}, kind: commandVersion},
		{
			name: "confirmed baseline",
			args: []string{"force", "1", "--confirm-existing-baseline"},
			kind: commandForceV1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command, err := parseCommand(test.args)
			if err != nil {
				t.Fatalf("parseCommand(%q) error = %v", test.args, err)
			}
			if command.kind != test.kind {
				t.Fatalf("kind = %v, want %v", command.kind, test.kind)
			}
			if test.name == "confirmed production up" && !command.confirmProduction {
				t.Fatal("confirmProduction = false, want true")
			}
		})
	}
}

func TestParseCommandRejectsAlternateCommands(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"up", "extra"},
		{"up", "--confirm-production=true"},
		{"up", "--confirm-production", "extra"},
		{"version", "extra"},
		{"force"},
		{"force", "2", "--confirm-existing-baseline"},
		{"force", "1", "--confirm-existing-baseline", "extra"},
		{"force", "--confirm-existing-baseline", "1"},
		{"force", "1", "--confirm-existing-baseline=true"},
		{"down"},
	} {
		if _, err := parseCommand(args); err == nil {
			t.Errorf("parseCommand(%q) error = nil, want usage error", args)
		}
	}
}

func TestPostgresURLEscapesCredentials(t *testing.T) {
	const testPassword = "p@ss:/?#[]% word" //nolint:gosec // Deliberately exercises URL escaping with a non-secret test value.
	connectionString := postgresURL(&config.Config{
		DBHost:     "db.example.test",
		DBPort:     "5432",
		DBUser:     "migration user",
		DBPassword: testPassword,
		DBName:     "sastlink",
		DBSSLMode:  "require",
	})

	connection, err := url.Parse(connectionString)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", connectionString, err)
	}
	if connection.User.Username() != "migration user" {
		t.Fatalf("username = %q, want %q", connection.User.Username(), "migration user")
	}
	password, ok := connection.User.Password()
	if !ok || password != testPassword {
		t.Fatalf("password = %q, %t; want original password", password, ok)
	}
	if connection.Query().Get("sslmode") != "require" {
		t.Fatalf("sslmode = %q, want %q", connection.Query().Get("sslmode"), "require")
	}
}
