package auth

import (
	"crypto/rand"
	"io"
	"time"
)

// RandomSource provides cryptographically strong random bytes.
type RandomSource interface {
	Read([]byte) (int, error)
}

// Clock provides the current time.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

// CryptoRandom is the default random source.
var CryptoRandom RandomSource = rand.Reader

// SystemClock is the default wall-clock source.
var SystemClock Clock = systemClock{}

func (systemClock) Now() time.Time { return time.Now() }

func randomBytes(source RandomSource, size int) ([]byte, error) {
	if source == nil {
		source = CryptoRandom
	}
	bytes := make([]byte, size)
	if _, err := io.ReadFull(source, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

func now(clock Clock) time.Time {
	if clock == nil {
		clock = SystemClock
	}
	return clock.Now()
}
