package sessionhandler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// cardDTO is the public card payload. Per PRD §10.1 the card endpoint returns
// these fields directly rather than inside the standard envelope.
type cardDTO struct {
	ID         int64   `json:"id"`
	Nickname   *string `json:"nickname"`
	Department *string `json:"department"`
	Intro      *string `json:"intro"`
	Avatar     *string `json:"avatar"`
	BlogURL    *string `json:"blog_url"`
	GitHubURL  *string `json:"github_url"`
}

func (h Handler) Card(c *gin.Context) {
	userID, ok := parsePositiveID(c.Param("id"))
	if !ok {
		response.Error(c, notFound(errcode.CodeUserNotFound, "用户不存在"))
		return
	}
	result, err := h.Service.Card(c.Request.Context(), session.CardInput{UserID: userID})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	// PRD §10.1 exempts the card endpoint from the standard envelope: the payload
	// is returned as-is so static consumers (homepage friend links, the OIDC
	// profile claim target) can read it without unwrapping.
	c.JSON(http.StatusOK, cardDTO{
		ID:         result.Card.ID,
		Nickname:   result.Card.Nickname,
		Department: result.Card.Department,
		Intro:      result.Card.Intro,
		Avatar:     result.Card.Avatar,
		BlogURL:    result.Card.BlogURL,
		GitHubURL:  result.Card.GitHubURL,
	})
}

// parsePositiveID parses a path ID, accepting only a canonical run of decimal
// digits denoting a positive value.
//
// The explicit digit check is not redundant with ParseInt: ParseInt accepts a
// leading sign, so "+12" (reachable as the percent-encoded %2B12) would resolve
// to identity 12 and give the same row two spellings in URLs and audit logs.
// Overflow and empty input fall out of ParseInt itself.
func parsePositiveID(raw string) (int64, bool) {
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

// notFound builds a 404 for the paths that reject an ID before reaching the
// service. The code is a parameter because the two callers differ: a missing user
// is 40401, while a missing binding record is the generic 40400 so it cannot be
// told apart from a record belonging to someone else.
func notFound(code int, message string) error {
	return &response.BusinessError{HTTPStatus: http.StatusNotFound, Code: code, Message: message}
}
