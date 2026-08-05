// Command loadmix drives realistic mixed traffic against a running SAST Link API
// on the 1c1g bench container, the way a campus app actually uses it. It is a
// bench harness, not production code: it reads verification codes from Redis in
// setup mode (the one place it is not strictly black-box) so a pool of accounts
// can be created through the real registration flow.
//
// Subcommands:
//
//	setup   -users N -redis ... : register a pool of N users via the real API
//	mix     -conc N -duration D : realistic session mix (reads + refresh + login + oauth)
//	refresh -conc N -duration D : pure refresh steady-state wall (isolates the audit fsync)
//	burst   -login N -read M    : login rush against background readers
//
// Every latency number is reported as p50/p99/p999 of the path being exercised.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

const (
	defaultBase  = "http://127.0.0.1:8080"
	defaultPool  = "pool.json"
	defaultRedis = "127.0.0.1:16379"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: loadmix <setup|mix|refresh|burst> [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "mix":
		err = cmdMix(os.Args[2:])
	case "refresh":
		err = cmdRefresh(os.Args[2:])
	case "burst":
		err = cmdBurst(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

// benchFlags holds the flags shared across subcommands.
type benchFlags struct {
	base  string
	pool  string
	users int
	conc  int
	dur   int
}

func newBenchFlags(fs *flag.FlagSet) *benchFlags {
	bf := &benchFlags{}
	fs.StringVar(&bf.base, "base", defaultBase, "API base URL")
	fs.StringVar(&bf.pool, "pool", defaultPool, "path to the user pool JSON file")
	fs.IntVar(&bf.users, "users", 200, "user pool size")
	fs.IntVar(&bf.conc, "conc", 100, "concurrency / simulated sessions")
	fs.IntVar(&bf.dur, "duration", 60, "run duration in seconds")
	return bf
}
