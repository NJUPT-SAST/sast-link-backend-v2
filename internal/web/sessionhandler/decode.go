package sessionhandler

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

const maxJSONRequestBodyBytes int64 = 64 << 10

var (
	errInvalidJSONContentType = errors.New("request Content-Type must be application/json")
	errTrailingJSONValue      = errors.New("JSON request body contains multiple values")
)

// decodeStrictJSON applies the shared request-body policy for session JSON APIs.
func decodeStrictJSON(c *gin.Context, destination any) error {
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errInvalidJSONContentType
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxJSONRequestBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errTrailingJSONValue
	}
	return binding.Validator.ValidateStruct(destination)
}
