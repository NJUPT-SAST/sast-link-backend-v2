package oauthloginhandler

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestAppCodeReadBudgetInterruptsSlowBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Inject a short outer deadline to test the real net/http body read without
	// making every run wait for the production eight-second budget.
	router.Use(func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 100*time.Millisecond)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	service := &fakeService{}
	router.POST("/app-code", (Handler{Service: service}).AppCodeLogin)
	server := httptest.NewUnstartedServer(router)
	server.Config.WriteTimeout = time.Second
	server.Start()
	defer server.Close()
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = fmt.Fprint(conn, "POST /app-code HTTP/1.1\r\nHost: fixture\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", response.StatusCode)
	}
}
