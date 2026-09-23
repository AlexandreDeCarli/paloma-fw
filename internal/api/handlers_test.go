package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleHealth(t *testing.T) {
	srv := NewServer(Config{})
	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()

	srv.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if rr.Body.String() != `{"status":"ok"}` {
		t.Errorf("unexpected body: %s", rr.Body.String())
	}
}

func TestRequireInternalSecret(t *testing.T) {
	srv := NewServer(Config{
		InternalSecret: "super-secret-token",
	})

	handler := srv.RequireInternalSecret(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authorized"))
	})

	// 1. Missing secret
	req1 := httptest.NewRequest("POST", "/api/internal/event", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusForbidden {
		t.Errorf("expected 403 on missing secret, got %d", rr1.Code)
	}

	// 2. Wrong secret
	req2 := httptest.NewRequest("POST", "/api/internal/event", nil)
	req2.Header.Set("X-Internal-Secret", "wrong")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("expected 403 on wrong secret, got %d", rr2.Code)
	}

	// 3. Valid secret
	req3 := httptest.NewRequest("POST", "/api/internal/event", nil)
	req3.Header.Set("X-Internal-Secret", "super-secret-token")
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Errorf("expected 200 on valid secret, got %d", rr3.Code)
	}
}

func TestHandleLogin(t *testing.T) {
	srv := NewServer(Config{
		AdminPassword: "test-admin-password",
	})

	// 1. Invalid password
	body1 := bytes.NewBufferString(`{"password":"wrong"}`)
	req1 := httptest.NewRequest("POST", "/api/auth/login", body1)
	rr1 := httptest.NewRecorder()
	srv.handleLogin(rr1, req1)
	if rr1.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 on wrong password, got %d", rr1.Code)
	}

	// 2. Valid password
	body2 := bytes.NewBufferString(`{"password":"test-admin-password"}`)
	req2 := httptest.NewRequest("POST", "/api/auth/login", body2)
	rr2 := httptest.NewRecorder()
	srv.handleLogin(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("expected 200 on right password, got %d", rr2.Code)
	}

	cookie := rr2.Result().Cookies()
	if len(cookie) == 0 || cookie[0].Name != "paloma_fw_session" {
		t.Errorf("expected paloma_fw_session cookie to be set")
	}
}
