package alumnihandler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/alumnirequest"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/alumnihandler"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/middleware"
)

// stubService records what the handler passed down and returns canned answers.
type stubService struct {
	submitInput alumnirequest.SubmitInput
	submitErr   error
	listInput   alumnirequest.ListInput
	listResult  *alumnirequest.ListResult
	listErr     error
	getView     *alumnirequest.RequestView
	getErr      error
	reviewInput alumnirequest.ReviewInput
	approveErr  error
	rejectErr   error
	resendErr   error
}

func (s *stubService) Submit(
	_ context.Context,
	input alumnirequest.SubmitInput,
) (*alumnirequest.SubmitResult, error) {
	s.submitInput = input
	if s.submitErr != nil {
		return nil, s.submitErr
	}
	return &alumnirequest.SubmitResult{RequestID: 7}, nil
}

func (s *stubService) List(
	_ context.Context,
	input alumnirequest.ListInput,
) (*alumnirequest.ListResult, error) {
	s.listInput = input
	if s.listErr != nil {
		return nil, s.listErr
	}
	if s.listResult != nil {
		return s.listResult, nil
	}
	return &alumnirequest.ListResult{
		Requests: []alumnirequest.RequestView{}, Total: 0, Page: 1, PageSize: 20,
	}, nil
}

func (s *stubService) Get(_ context.Context, _ int64) (*alumnirequest.RequestView, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.getView, nil
}

func (s *stubService) Approve(
	_ context.Context,
	input alumnirequest.ReviewInput,
) (*alumnirequest.ApproveResult, error) {
	s.reviewInput = input
	if s.approveErr != nil {
		return nil, s.approveErr
	}
	return &alumnirequest.ApproveResult{
		UserID: 42, LoginEmail: "b20040101@njupt.edu.cn", NotifyEnqueued: true,
	}, nil
}

func (s *stubService) Reject(
	_ context.Context,
	input alumnirequest.ReviewInput,
) (*alumnirequest.ReviewResult, error) {
	s.reviewInput = input
	if s.rejectErr != nil {
		return nil, s.rejectErr
	}
	return &alumnirequest.ReviewResult{NotifyEnqueued: true}, nil
}

func (s *stubService) ResendNotification(
	_ context.Context,
	input alumnirequest.ReviewInput,
) (*alumnirequest.ReviewResult, error) {
	s.reviewInput = input
	if s.resendErr != nil {
		return nil, s.resendErr
	}
	return &alumnirequest.ReviewResult{NotifyEnqueued: true}, nil
}

// newRouter mounts the routes with passthrough gates and a fixed principal, so the
// tests exercise the handler rather than the middleware.
func newRouter(service *stubService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	passthrough := func(c *gin.Context) {
		middleware.SetPrincipal(c, middleware.Principal{UserID: 99, ClientID: "sast-link-web"})
		c.Next()
	}
	alumnihandler.RegisterRoutes(router, alumnihandler.Handler{Requests: service},
		alumnihandler.Gates{
			RequireAuth:       passthrough,
			RequireReadScope:  func(c *gin.Context) { c.Next() },
			RequireWriteScope: func(c *gin.Context) { c.Next() },
			RequireAdmin:      func(c *gin.Context) { c.Next() },
			RequireReader:     func(c *gin.Context) { c.Next() },
		})
	return router
}

func doJSON(t *testing.T, router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(context.Background(), method, path,
		bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func validSubmitBody() string {
	return `{"name":"张三","student_id":"B20040101",
		"login_email":"b20040101@njupt.edu.cn","personal_email":"zhangsan@example.com",
		"phone_number":"13800000000","qq_number":"10001","major":"计算机科学与技术",
		"join_year":"2020","captcha_token":"token"}`
}

func TestSubmitPassesInputThroughAndReturnsTheID(t *testing.T) {
	t.Parallel()

	service := &stubService{}
	recorder := doJSON(t, newRouter(service), http.MethodPost, "/alumni-requests", validSubmitBody())
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", recorder.Code, recorder.Body)
	}
	var envelope struct {
		Code int `json:"code"`
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if envelope.Code != 0 || envelope.Data.ID != 7 {
		t.Fatalf("envelope = %+v, want code 0 and id 7", envelope)
	}
	if service.submitInput.CaptchaToken != "token" {
		t.Fatalf("captcha token = %q, want it forwarded", service.submitInput.CaptchaToken)
	}
	// The client address comes from the request, not the body: a submitter must not
	// be able to choose the value the rate limiter buckets them under.
	if service.submitInput.ClientIP == "" {
		t.Fatal("client ip was not captured from the request")
	}
}

// A submission naming a reviewer-owned field is refused outright rather than
// having it ignored, so a submitter cannot appear to set their own status.
func TestSubmitRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	body := `{"name":"张三","student_id":"B20040101","status":"approved"}`
	recorder := doJSON(t, newRouter(&stubService{}), http.MethodPost, "/alumni-requests", body)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown field", recorder.Code)
	}
}

func TestSubmitRequiresJSONContentType(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/alumni-requests", strings.NewReader(validSubmitBody()))
	request.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()
	newRouter(&stubService{}).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-JSON content type", recorder.Code)
	}
}

// The two captcha outcomes must reach the client as different statuses: 400 means
// solve it again, 503 means verification is not running and the entry point should
// be hidden.
func TestSubmitMapsCaptchaOutcomesToDistinctStatuses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   int
	}{
		{
			name: "rejected token",
			err: &alumnirequest.Error{
				Kind: alumnirequest.KindCaptchaFailed,
				Code: errcode.CodeCaptchaFailed, Message: "人机校验未通过，请重试",
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   errcode.CodeCaptchaFailed,
		},
		{
			name: "verification unavailable",
			err: &alumnirequest.Error{
				Kind: alumnirequest.KindUnavailable,
				Code: errcode.CodeAlumniRequestUnavailable, Message: "申请通道暂不可用，请稍后再试",
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   errcode.CodeAlumniRequestUnavailable,
		},
		{
			name: "rate limited",
			err: &alumnirequest.Error{
				Kind: alumnirequest.KindRateLimited,
				Code: errcode.CodeRateLimited, Message: "提交过于频繁，请稍后再试",
			},
			wantStatus: http.StatusTooManyRequests,
			wantCode:   errcode.CodeRateLimited,
		},
		{
			name: "already pending",
			err: &alumnirequest.Error{
				Kind: alumnirequest.KindConflict,
				Code: errcode.CodeAlumniRequestPending, Message: "该学号已有待审申请，请等待处理",
			},
			wantStatus: http.StatusConflict,
			wantCode:   errcode.CodeAlumniRequestPending,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			recorder := doJSON(t, newRouter(&stubService{submitErr: testCase.err}),
				http.MethodPost, "/alumni-requests", validSubmitBody())
			if recorder.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", recorder.Code, testCase.wantStatus, recorder.Body)
			}
			var envelope struct {
				Code int `json:"code"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if envelope.Code != testCase.wantCode {
				t.Fatalf("business code = %d, want %d", envelope.Code, testCase.wantCode)
			}
		})
	}
}

func TestListForwardsFilters(t *testing.T) {
	t.Parallel()

	service := &stubService{}
	recorder := doJSON(t, newRouter(service), http.MethodGet,
		"/admin/alumni-requests?status=pending&notified=false&keyword=%E5%BC%A0&page=2&page_size=30", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", recorder.Code, recorder.Body)
	}
	if service.listInput.Status == nil || *service.listInput.Status != "pending" {
		t.Fatalf("status filter = %v, want pending", service.listInput.Status)
	}
	if service.listInput.Notified == nil || *service.listInput.Notified {
		t.Fatalf("notified filter = %v, want false", service.listInput.Notified)
	}
	if service.listInput.Page != 2 || service.listInput.PageSize != 30 {
		t.Fatalf("paging = %d/%d, want 2/30", service.listInput.Page, service.listInput.PageSize)
	}
}

// A mistyped notified=ture must not be read as false: that would return the
// opposite of what was asked and look like an empty backlog.
func TestListRejectsAnUnparseableNotifiedFilter(t *testing.T) {
	t.Parallel()

	recorder := doJSON(t, newRouter(&stubService{}), http.MethodGet,
		"/admin/alumni-requests?notified=ture", "")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unparseable notified value", recorder.Code)
	}
}

// An empty queue serializes as [] rather than null, so clients need no special
// case for it.
func TestListSerializesAnEmptyQueueAsAnArray(t *testing.T) {
	t.Parallel()

	recorder := doJSON(t, newRouter(&stubService{}), http.MethodGet, "/admin/alumni-requests", "")
	if !strings.Contains(recorder.Body.String(), `"requests":[]`) {
		t.Fatalf("body = %s, want an empty array", recorder.Body)
	}
}

// The reviewer's identity comes from the authenticated principal, never the body.
func TestApproveTakesTheReviewerFromThePrincipal(t *testing.T) {
	t.Parallel()

	service := &stubService{}
	recorder := doJSON(t, newRouter(service), http.MethodPost,
		"/admin/alumni-requests/5/approve", `{}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", recorder.Code, recorder.Body)
	}
	if service.reviewInput.AdminUserID != 99 {
		t.Fatalf("reviewer = %d, want the principal's user id", service.reviewInput.AdminUserID)
	}
	if service.reviewInput.ActorClientID != "sast-link-web" {
		t.Fatalf("actor client = %q, want the principal's azp", service.reviewInput.ActorClientID)
	}
	if service.reviewInput.RequestID != 5 {
		t.Fatalf("request id = %d, want 5", service.reviewInput.RequestID)
	}
}

// The approval response must not carry a credential: the generated password is
// discarded at approval time and the applicant sets their own.
func TestApproveResponseCarriesNoPassword(t *testing.T) {
	t.Parallel()

	recorder := doJSON(t, newRouter(&stubService{}), http.MethodPost,
		"/admin/alumni-requests/5/approve", `{}`)
	body := recorder.Body.String()
	for _, forbidden := range []string{"password", "initial_password"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response mentions %q: %s", forbidden, body)
		}
	}
	if !strings.Contains(body, `"notify_enqueued":true`) {
		t.Fatalf("body = %s, want the notification status reported", body)
	}
}

// A second verdict on a decided ticket is 422, not 409: the ticket exists and the
// request is well formed, the transition is what its status refuses.
func TestApproveMapsAnAlreadyReviewedTicketTo422(t *testing.T) {
	t.Parallel()

	service := &stubService{approveErr: &alumnirequest.Error{
		Kind: alumnirequest.KindStateConflict,
		Code: errcode.CodeAlumniRequestReviewed, Message: "该申请已被处理",
	}}
	recorder := doJSON(t, newRouter(service), http.MethodPost,
		"/admin/alumni-requests/5/approve", `{}`)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (%s)", recorder.Code, recorder.Body)
	}
}

func TestRejectForwardsTheReason(t *testing.T) {
	t.Parallel()

	service := &stubService{}
	recorder := doJSON(t, newRouter(service), http.MethodPost,
		"/admin/alumni-requests/5/reject", `{"reject_reason":"学号与姓名不匹配"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", recorder.Code, recorder.Body)
	}
	if service.reviewInput.Reason != "学号与姓名不匹配" {
		t.Fatalf("reason = %q, want it forwarded", service.reviewInput.Reason)
	}
}

// A non-numeric id names no ticket, so it is a 404 rather than a 400.
func TestReviewRoutesAnswer404ForANonNumericID(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/admin/alumni-requests/abc",
		"/admin/alumni-requests/abc/approve",
		"/admin/alumni-requests/abc/reject",
		"/admin/alumni-requests/abc/resend-notification",
	} {
		method := http.MethodGet
		body := ""
		if strings.HasSuffix(path, "approve") || strings.HasSuffix(path, "reject") ||
			strings.HasSuffix(path, "resend-notification") {
			method = http.MethodPost
			body = `{}`
		}
		recorder := doJSON(t, newRouter(&stubService{}), method, path, body)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s %s: status = %d, want 404", method, path, recorder.Code)
		}
	}
}

// The queue read omits the submitter's address: it is kept for abuse tracing, and
// reviewing a ticket has no use for a network identifier tied to a named person.
func TestListNeverReturnsTheSubmitterAddress(t *testing.T) {
	t.Parallel()

	service := &stubService{listResult: &alumnirequest.ListResult{
		Requests: []alumnirequest.RequestView{{
			ID: 7, Name: "张三", StudentID: "B20040101",
			LoginEmail: "b20040101@njupt.edu.cn", PersonalEmail: "zhangsan@example.com",
			Status: "pending",
		}},
		Total: 1, Page: 1, PageSize: 20,
	}}
	recorder := doJSON(t, newRouter(service), http.MethodGet, "/admin/alumni-requests", "")
	body := recorder.Body.String()
	if strings.Contains(body, "client_ip") {
		t.Fatalf("response carries client_ip: %s", body)
	}
	// The notification fields are present, since the console filters on them.
	for _, want := range []string{"notified_at", "notify_attempts"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q: %s", want, body)
		}
	}
}
