// Package web holds helpers shared by the HTTP handler layers.
package web

import "strconv"

// ParsePositiveID parses a path or query segment as a positive primary key.
//
// Strict digits only: the admin and session surfaces must agree on what a valid
// id looks like, and a path segment with surrounding whitespace was never a
// meaningful resource — accepting it while the other surface refuses it makes
// the same URL answer differently depending on which handler it hits.
// Overflow and empty input fall out of ParseInt itself.
func ParsePositiveID(raw string) (int64, bool) {
	if raw == "" {
		return 0, false
	}
	for _, symbol := range raw {
		if symbol < '0' || symbol > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, false
	}
	return value, true
}
