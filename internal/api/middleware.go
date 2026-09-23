package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// SessionManager manages authenticated browser sessions
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]time.Time
	duration time.Duration
}

// NewSessionManager creates a session store
func NewSessionManager(duration time.Duration) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]time.Time),
		duration: duration,
	}
	// Background cleanup of expired sessions
	go sm.cleanupLoop()
	return sm
}

func (sm *SessionManager) CreateSession() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[token] = time.Now().Add(sm.duration)
	return token, nil
}

func (sm *SessionManager) ValidateSession(token string) bool {
	if token == "" {
		return false
	}
	sm.mu.RLock()
	expiry, exists := sm.sessions[token]
	sm.mu.RUnlock()

	if !exists || time.Now().After(expiry) {
		if exists {
			sm.DeleteSession(token)
		}
		return false
	}
	return true
}

func (sm *SessionManager) DeleteSession(token string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, token)
}

func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		now := time.Now()
		sm.mu.Lock()
		for t, exp := range sm.sessions {
			if now.After(exp) {
				delete(sm.sessions, t)
			}
		}
		sm.mu.Unlock()
	}
}

// SecurityHeadersMiddleware sets strict production security headers
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// RequireAuth checks for a valid session cookie
func (s *Server) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("paloma_fw_session")
		if err != nil || !s.sessions.ValidateSession(cookie.Value) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// RequireInternalSecret checks the X-Internal-Secret header using constant time comparison
func (s *Server) RequireInternalSecret(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret := r.Header.Get("X-Internal-Secret")
		if secret == "" {
			secret = r.URL.Query().Get("secret")
		}

		if s.internalSecret == "" || subtle.ConstantTimeCompare([]byte(secret), []byte(s.internalSecret)) != 1 {
			http.Error(w, `{"error":"forbidden: invalid internal secret"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
