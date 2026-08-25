package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// apiError carries the HTTP status of a non-2xx response so the driver can count
// 429 (rate limit) separately from 401 (auth) in its error report.
type apiError struct {
	Status int
	Body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body) }

func httpError(status int, data []byte) *apiError {
	return &apiError{Status: status, Body: truncate(data)}
}

// apiClient is a keep-alive HTTP client for the SAST Link API. Connection reuse
// matters: per-request TCP setup at thousands of requests a second would throttle
// the driver, not the service under test.
type apiClient struct {
	base string
	http *http.Client
}

func newAPIClient(base string) *apiClient {
	transport := &http.Transport{
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 512,
		IdleConnTimeout:     90 * time.Second,
	}
	return &apiClient{
		base: base,
		http: &http.Client{Transport: transport, Timeout: 60 * time.Second},
	}
}

// envelope is the standard {code, message, data} response shape.
type envelope struct {
	Code int             `json:"code"`
	Data json.RawMessage `json:"data"`
}

func (c *apiClient) do(ctx context.Context, method, path string, headers map[string]string, body []byte) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func parseTokens(data []byte) (tokenPair, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return tokenPair{}, fmt.Errorf("decode envelope: %w", err)
	}
	if env.Code != 0 {
		return tokenPair{}, fmt.Errorf("business error code %d", env.Code)
	}
	var pair tokenPair
	if err := json.Unmarshal(env.Data, &pair); err != nil {
		return tokenPair{}, fmt.Errorf("decode token pair: %w", err)
	}
	return pair, nil
}

func (c *apiClient) login(ctx context.Context, email, password string) (tokenPair, error) {
	body, _ := json.Marshal(map[string]string{"login_email": email, "password": password})
	status, data, err := c.do(ctx, http.MethodPost, "/user/login", nil, body)
	if err != nil {
		return tokenPair{}, err
	}
	if status != http.StatusOK {
		return tokenPair{}, httpError(status, data)
	}
	return parseTokens(data)
}

func (c *apiClient) refresh(ctx context.Context, refreshToken string) (tokenPair, error) {
	body, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	status, data, err := c.do(ctx, http.MethodPost, "/auth/refresh", nil, body)
	if err != nil {
		return tokenPair{}, err
	}
	if status != http.StatusOK {
		return tokenPair{}, httpError(status, data)
	}
	return parseTokens(data)
}

func (c *apiClient) profile(ctx context.Context, accessToken string) (int, error) {
	status, _, err := c.do(ctx, http.MethodGet, "/user/profile",
		map[string]string{"Authorization": "Bearer " + accessToken}, nil)
	return status, err
}

// oauthToken exercises POST /oauth/token with the refresh grant against the
// built-in public client, the same family a third-party confidential client's
// token request rides on.
func (c *apiClient) oauthToken(ctx context.Context, refreshToken string) (tokenPair, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", "sast-link-web")
	status, data, err := c.do(ctx, http.MethodPost, "/oauth/token", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}, []byte(form.Encode()))
	if err != nil {
		return tokenPair{}, err
	}
	if status != http.StatusOK {
		return tokenPair{}, httpError(status, data)
	}
	// /oauth/token answers RFC 6749 directly (no {code, data} envelope).
	var pair tokenPair
	if err := json.Unmarshal(data, &pair); err != nil {
		return tokenPair{}, fmt.Errorf("decode oauth token response: %w", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		return tokenPair{}, fmt.Errorf("oauth token response missing tokens: %s", truncate(data))
	}
	return pair, nil
}

func (c *apiClient) sendRegisterCode(ctx context.Context, email string) error {
	body, _ := json.Marshal(map[string]string{"login_email": email})
	status, data, err := c.do(ctx, http.MethodPost, "/auth/register/send-code", nil, body)
	if err != nil {
		return err
	}
	// The code is written to Redis before the mailer call, so a 5xx from the
	// failed SMTP send leaves the code readable — setup reads it from Redis and
	// the registration can still complete. A 4xx (validation or rate limit)
	// means the code was never stored, which is the only fatal case.
	if status >= 500 {
		return nil
	}
	if status != http.StatusOK {
		return httpError(status, data)
	}
	return nil
}

func (c *apiClient) verifyRegisterCode(ctx context.Context, email, code string) (string, error) {
	body, _ := json.Marshal(map[string]string{"login_email": email, "code": code})
	status, data, err := c.do(ctx, http.MethodPost, "/auth/register/verify-code", nil, body)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", httpError(status, data)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return "", err
	}
	var out struct {
		RegisterTicket string `json:"register_ticket"`
	}
	if err := json.Unmarshal(env.Data, &out); err != nil {
		return "", err
	}
	if out.RegisterTicket == "" {
		return "", fmt.Errorf("verify-code returned no ticket")
	}
	return out.RegisterTicket, nil
}

func (c *apiClient) register(ctx context.Context, ticket, email, password, name, studentID, college, major string) (tokenPair, error) {
	body, _ := json.Marshal(map[string]string{
		"register_ticket": ticket,
		"password":        password,
		"name":            name,
		"student_id":      studentID,
		"phone_number":    "13800138000",
		"qq_number":       "100000",
		"college":         college,
		"major":           major,
	})
	status, data, err := c.do(ctx, http.MethodPost, "/auth/register", nil, body)
	if err != nil {
		return tokenPair{}, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return tokenPair{}, httpError(status, data)
	}
	return parseTokens(data)
}

func truncate(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 160 {
		return s[:160]
	}
	return s
}
