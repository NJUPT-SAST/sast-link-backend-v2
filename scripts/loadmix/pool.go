package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// poolEntry is one registered test account, persisted between setup and the
// load subcommands.
type poolEntry struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type pool struct {
	Entries []poolEntry `json:"entries"`
}

func savePool(path string, p pool) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func loadPool(path string) (pool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return pool{}, err
	}
	var p pool
	if err := json.Unmarshal(data, &p); err != nil {
		return pool{}, fmt.Errorf("decode pool %s: %w", path, err)
	}
	if len(p.Entries) == 0 {
		return pool{}, fmt.Errorf("pool %s is empty; run `loadmix setup` first", path)
	}
	return p, nil
}
