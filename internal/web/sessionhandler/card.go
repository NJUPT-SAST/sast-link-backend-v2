package sessionhandler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web"
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
	userID, ok := web.ParsePositiveID(c.Param("id"))
	if !ok {
		response.Error(c, notFound(errcode.CodeUserNotFound, "用户不存在"))
		return
	}
	result, err := h.Service.Card(c.Request.Context(), session.CardInput{
		UserID:   userID,
		ClientIP: c.ClientIP(),
	})
	if err != nil {
		response.Error(c, mapServiceError(err))
		return
	}
	// PRD §10.1 exempts the card endpoint from the standard envelope: the payload
	// is returned as-is so static consumers (homepage friend links) can read it
	// without unwrapping.
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

// notFound builds a 404 for the paths that reject an ID before reaching the
// service. The code is a parameter because the two callers differ: a missing user
// is 40401, while a missing binding record is the generic 40400 so it cannot be
// told apart from a record belonging to someone else.
func notFound(code int, message string) error {
	return &response.BusinessError{HTTPStatus: http.StatusNotFound, Code: code, Message: message}
}
