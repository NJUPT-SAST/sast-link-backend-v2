package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestParsePaging(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, test := range []struct {
		name         string
		query        string
		wantPage     int
		wantPageSize int
		wantErr      bool
	}{
		{"absent", "", 0, 0, false},
		{"explicit", "page=3&page_size=25", 3, 25, false},
		{"page size at cap", "page=1&page_size=100", 1, 100, false},
		{"page size over cap", "page=1&page_size=101", 0, 0, true},
		{"page zero", "page=0&page_size=20", 0, 0, true},
		{"page negative", "page=-1&page_size=20", 0, 0, true},
		{"page unparseable", "page=abc&page_size=20", 0, 0, true},
		{"page size unparseable", "page=1&page_size=abc", 0, 0, true},
		{"page size zero", "page=1&page_size=0", 0, 0, true},
		{"page size negative", "page=1&page_size=-1", 0, 0, true},
		{"page overflow", "page=4611686018427387905&page_size=20", 0, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				"/?"+test.query, nil)

			page, pageSize, err := ParsePaging(c)
			if test.wantErr {
				if err == nil {
					t.Fatalf("ParsePaging() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePaging() error = %v, want nil", err)
			}
			if page != test.wantPage || pageSize != test.wantPageSize {
				t.Fatalf("ParsePaging() = %d/%d, want %d/%d",
					page, pageSize, test.wantPage, test.wantPageSize)
			}
		})
	}
}
