package sessionhandler

// GET /card/:id is temporarily disabled pending a privacy redesign (its
// sequential-ID public URL lets anyone enumerate the full member roster). The
// handler tests below exercised that disabled endpoint, so they are commented
// out with it and will be rewritten for the new design.
//
// Disabled tests:
//   - TestCardReturnsBarePayload
//   - TestCardIsPublic
//   - TestCardRejectsMalformedID
//   - TestCardUnknownUserMatchesMalformedID

/*
func TestCardReturnsBarePayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{cardResult: &session.CardResult{Card: session.CardDTO{
		ID: 1, Nickname: stringPtr("张三"), Department: stringPtr("software"),
		Intro: stringPtr("自我介绍"), Avatar: stringPtr("https://cos.example.com/avatar/1.jpg"),
	}}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodGet, "/card/1", "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode card: %v; body=%s", err, recorder.Body.String())
	}
	if _, wrapped := payload["code"]; wrapped {
		t.Fatalf("body = %s, want no envelope", recorder.Body.String())
	}
	if payload["id"] != float64(1) || payload["nickname"] != "张三" {
		t.Fatalf("payload = %#v", payload)
	}
	if payload["blog_url"] != nil {
		t.Fatalf("blog_url = %#v, want null", payload["blog_url"])
	}
	if service.cardInput.UserID != 1 {
		t.Fatalf("user id = %d, want 1", service.cardInput.UserID)
	}
}

func TestCardIsPublic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{cardResult: &session.CardResult{Card: session.CardDTO{ID: 7}}}
	router := gin.New()
	RegisterRoutes(router, Handler{Service: service}, scopedGates(func(c *gin.Context) {
		response.Error(c, &response.BusinessError{
			HTTPStatus: http.StatusUnauthorized, Code: errcode.CodeUnauthenticated, Message: "未登录",
		})
		c.Abort()
	}))
	recorder := doJSON(router, http.MethodGet, "/card/7", "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 without auth; body=%s", recorder.Code, recorder.Body.String())
	}
	if service.cardCalls != 1 {
		t.Fatalf("service called %d times, want 1", service.cardCalls)
	}
}

func TestCardRejectsMalformedID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodGet, "/card/abc", "")

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusNotFound || body.Code != errcode.CodeUserNotFound {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	if service.cardCalls != 0 {
		t.Fatalf("service called %d times, want 0", service.cardCalls)
	}
}

func TestCardUnknownUserMatchesMalformedID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	malformed := decodeBody(t, doJSON(authedRouter(&fakeService{}), http.MethodGet, "/card/abc", ""))
	unknown := decodeBody(t, doJSON(
		authedRouter(&fakeService{cardErr: session.ErrUserNotFound}),
		http.MethodGet, "/card/999999", "",
	))

	if malformed.Code != unknown.Code || malformed.Message != unknown.Message {
		t.Fatalf("malformed = %#v, unknown = %#v, want identical code and message", malformed, unknown)
	}
	if unknown.Code != errcode.CodeUserNotFound {
		t.Fatalf("code = %d, want %d", unknown.Code, errcode.CodeUserNotFound)
	}
	if unknown.Message != "用户不存在" {
		t.Fatalf("message = %q, want 用户不存在", unknown.Message)
	}
}
*/
