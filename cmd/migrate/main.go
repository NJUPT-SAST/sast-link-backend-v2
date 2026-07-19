// Command migrate applies, inspects, or guards the V001 database baseline.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"

	"github.com/golang-migrate/migrate/v4"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/config"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/migration"
)

type commandKind uint8

const (
	commandUp commandKind = iota + 1
	commandVersion
	commandForceV1
)

type command struct {
	kind              commandKind
	confirmProduction bool
}

const usage = "usage: migrate <up [--confirm-production]|version|force 1 --confirm-existing-baseline>"

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	parsedCommand, err := parseCommand(args)
	if err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	databaseURL := postgresURL(cfg)

	switch parsedCommand.kind {
	case commandUp:
		if cfg.AppEnv == "production" && !parsedCommand.confirmProduction {
			return errors.New("migration up in production requires --confirm-production")
		}
		return runUp(databaseURL)
	case commandVersion:
		version, dirty, err := migration.Current(databaseURL)
		if err != nil {
			return err
		}
		_, err = fmt.Printf("version=%d dirty=%t\n", version, dirty)
		return err
	case commandForceV1:
		return migration.BaselineV1(context.Background(), databaseURL)
	default:
		return errors.New("unrecognized migration command")
	}
}

func parseCommand(args []string) (command, error) {
	switch {
	case len(args) == 1 && args[0] == "up":
		return command{kind: commandUp}, nil
	case len(args) == 2 && args[0] == "up" && args[1] == "--confirm-production":
		return command{kind: commandUp, confirmProduction: true}, nil
	case len(args) == 1 && args[0] == "version":
		return command{kind: commandVersion}, nil
	case len(args) == 3 && args[0] == "force" && args[1] == "1" && args[2] == "--confirm-existing-baseline":
		return command{kind: commandForceV1}, nil
	default:
		return command{}, errors.New(usage)
	}
}

func postgresURL(cfg *config.Config) string {
	connection := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.DBUser, cfg.DBPassword),
		Host:   net.JoinHostPort(cfg.DBHost, cfg.DBPort),
		Path:   "/" + cfg.DBName,
	}
	query := connection.Query()
	query.Set("sslmode", cfg.DBSSLMode)
	connection.RawQuery = query.Encode()
	return connection.String()
}

func runUp(databaseURL string) error {
	instance, err := migration.New(databaseURL)
	if err != nil {
		return err
	}
	defer func() { _, _ = instance.Close() }()

	if err := instance.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}
