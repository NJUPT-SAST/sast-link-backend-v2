// Package web holds helpers shared by the HTTP handler layers.
package web

import (
	"errors"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// ErrInvalidQueryParameter is returned when a query parameter is present but
// cannot be parsed according to the contract. Handler layers map it to 400.
var ErrInvalidQueryParameter = errors.New("invalid query parameter")

// MaxPageNumber bounds a requested page. The service turns page and page_size
// into an offset by multiplying them, which silently overflows for a large
// enough page: 4611686018427387905 wraps to offset 0, answering with the first
// page while echoing the page it was asked for, and other values wrap negative
// and surface as a 500 where the contract documents a 400.
//
// Rejecting rather than clamping: a caller asking for page 2^62 has made a
// mistake, and answering with some other page would hide it.
const MaxPageNumber = 1 << 30

// ParsePaging reads the page window from query parameters. An absent parameter
// is zero, which the service reads as "use the default"; a present but
// unparsable one, or a page_size above the contract maximum, is an error so
// the caller knows the request was rejected rather than silently adjusted.
func ParsePaging(c *gin.Context) (page, pageSize int, err error) {
	page, err = parsePageNumber(c.Query("page"))
	if err != nil {
		return 0, 0, err
	}
	pageSize, err = parseOptionalPositiveInt(c.Query("page_size"))
	if err != nil {
		return 0, 0, err
	}
	if pageSize > validate.MaxPageSize {
		return 0, 0, ErrInvalidQueryParameter
	}
	return page, pageSize, nil
}

// parsePageNumber reads a positive page number, rejecting values large enough
// to overflow the offset calculation.
func parsePageNumber(raw string) (int, error) {
	value, err := parseOptionalPositiveInt(raw)
	if err != nil {
		return 0, err
	}
	if value > MaxPageNumber {
		return 0, ErrInvalidQueryParameter
	}
	return value, nil
}

// parseOptionalPositiveInt reads a trimmed string as a positive integer. Empty
// input is treated as absent (zero). Anything else that is not a strictly
// positive integer is an error.
func parseOptionalPositiveInt(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil || value <= 0 {
		return 0, ErrInvalidQueryParameter
	}
	return value, nil
}

// ParsePositiveID parses a path or query segment as a positive primary key.
// Strict digits only: the admin and session surfaces must agree on what a valid
// id looks like, or the same URL answers differently depending on which handler
// it hits. Overflow and empty input fall out of ParseInt.
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
