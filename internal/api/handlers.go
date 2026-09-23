package api

import (
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/AlexandreDeCarli/paloma-fw/internal/db"
	"github.com/AlexandreDeCarli/paloma-fw/internal/fail2ban"
)

// Server coordinates HTTP routing, database queries, and fail2ban operations
type Server struct {
	store          *db.Store
	f2b            *fail2ban.Client
	adminPassword  string
	internalSecret string
	sessions       *SessionManager
	webFS          fs.FS
}

// Config defines the Server parameters
type Config struct {
	Store          *db.Store
	Fail2ban       *fail2ban.Client
	AdminPassword  string
	InternalSecret string
	WebFS          fs.FS
}

// NewServer instantiates a new HTTP server handler
func NewServer(cfg Config) *Server {
	return &Server{
		store:          cfg.Store,
		f2b:            cfg.Fail2ban,
		adminPassword:  cfg.AdminPassword,
		internalSecret: cfg.InternalSecret,
		sessions:       NewSessionManager(24 * time.Hour),
		webFS:          cfg.WebFS,
	}
}

// RegisterRoutes sets up all API and web routes
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// Public routes
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/auth/check", s.handleAuthCheck)

	// Internal webhook (protected by X-Internal-Secret)
	mux.HandleFunc("POST /api/internal/event", s.RequireInternalSecret(s.handleInternalEvent))

	// Protected routes (require session authentication)
	mux.HandleFunc("GET /api/bans", s.RequireAuth(s.handleGetBans))
	mux.HandleFunc("POST /api/bans/unban", s.RequireAuth(s.handleUnban))
	mux.HandleFunc("GET /api/events", s.RequireAuth(s.handleGetEvents))
	mux.HandleFunc("GET /api/metrics", s.RequireAuth(s.handleGetMetrics))

	// Static web assets
	if s.webFS != nil {
		fileServer := http.FileServer(http.FS(s.webFS))
		mux.Handle("GET /", fileServer)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

type loginRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
		return
	}

	if s.adminPassword == "" || subtle.ConstantTimeCompare([]byte(req.Password), []byte(s.adminPassword)) != 1 {
		time.Sleep(300 * time.Millisecond) // Thwart brute force timing
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	token, err := s.sessions.CreateSession()
	if err != nil {
		http.Error(w, `{"error":"failed to generate session"}`, http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "paloma_fw_session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "authenticated successfully",
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("paloma_fw_session"); err == nil {
		s.sessions.DeleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "paloma_fw_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}

func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("paloma_fw_session")
	authenticated := err == nil && s.sessions.ValidateSession(cookie.Value)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"authenticated": authenticated,
	})
}

func (s *Server) handleGetBans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bans, err := s.store.ListActiveBans(ctx)
	if err != nil {
		http.Error(w, `{"error":"failed to fetch bans from database"}`, http.StatusInternalServerError)
		return
	}

	// Also query live fail2ban status
	liveStatus, _ := s.f2b.GetStatus(ctx, "traefik-401")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"active_bans": bans,
		"live_status": liveStatus,
	})
}

type unbanRequest struct {
	IP    string `json:"ip"`
	Jail  string `json:"jail"`
	Notes string `json:"notes"`
}

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	var req unbanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
		return
	}

	cleanIP, err := fail2ban.ValidateIP(req.IP)
	if err != nil {
		http.Error(w, `{"error":"invalid ip address"}`, http.StatusBadRequest)
		return
	}

	jail := req.Jail
	if jail == "" {
		jail = "traefik-401"
	}

	ctx := r.Context()

	// 1. Trigger unban via Fail2ban socket
	if err := s.f2b.UnbanIP(ctx, jail, cleanIP); err != nil {
		log.Printf("[Warn] Fail2ban unban returned error (might be already unbanned): %v", err)
	}

	// 2. Update status in MySQL HeatWave
	if err := s.store.RecordUnban(ctx, cleanIP, jail, "admin_ui", req.Notes, true); err != nil {
		log.Printf("[Error] Failed to update unban in database: %v", err)
		http.Error(w, `{"error":"failed to update database"}`, http.StatusInternalServerError)
		return
	}

	// 3. Record audit log
	details := "Manual unban triggered via Paloma Shield Web Dashboard"
	if req.Notes != "" {
		details += " - Notes: " + req.Notes
	}
	_ = s.store.RecordAudit(ctx, "admin", "unban_ip", &cleanIP, &details)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "IP unbanned successfully",
		"ip":      cleanIP,
	})
}

func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	eventType := strings.TrimSpace(r.URL.Query().Get("type"))

	events, total, err := s.store.ListEvents(r.Context(), page, limit, search, eventType)
	if err != nil {
		http.Error(w, `{"error":"failed to fetch events"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"total":  total,
		"page":   page,
		"limit":  limit,
	})
}

func (s *Server) handleGetMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := s.store.GetMetrics(r.Context())
	if err != nil {
		http.Error(w, `{"error":"failed to fetch metrics"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

type internalEventPayload struct {
	Event           string `json:"event"` // ban or unban
	IP              string `json:"ip"`
	Jail            string `json:"jail"`
	Failures        int    `json:"failures"`
	DurationSeconds int    `json:"duration_seconds"`
	Reason          string `json:"reason"`
	Actor           string `json:"actor"`
}

func (s *Server) handleInternalEvent(w http.ResponseWriter, r *http.Request) {
	var payload internalEventPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	cleanIP, err := fail2ban.ValidateIP(payload.IP)
	if err != nil {
		http.Error(w, `{"error":"invalid ip"}`, http.StatusBadRequest)
		return
	}

	jail := payload.Jail
	if jail == "" {
		jail = "traefik-401"
	}

	ctx := r.Context()
	if payload.Event == "ban" {
		failures := payload.Failures
		if failures <= 0 {
			failures = 5
		}
		duration := payload.DurationSeconds
		if duration <= 0 {
			duration = 172800 // 48h
		}
		reason := payload.Reason
		if reason == "" {
			reason = "Excessive 401 Unauthorized errors on LiteLLM Proxy"
		}
		actor := payload.Actor
		if actor == "" {
			actor = "fail2ban"
		}

		if err := s.store.RecordBan(ctx, cleanIP, jail, failures, duration, reason, actor); err != nil {
			log.Printf("[Error] Failed to record ban in MySQL: %v", err)
			http.Error(w, `{"error":"failed to save to database"}`, http.StatusInternalServerError)
			return
		}
		log.Printf("[Event] Recorded ban for IP %s in jail %s", cleanIP, jail)
	} else if payload.Event == "unban" {
		actor := payload.Actor
		if actor == "" {
			actor = "fail2ban_timer"
		}
		if err := s.store.RecordUnban(ctx, cleanIP, jail, actor, "Unbanned automatically upon expiration", false); err != nil {
			log.Printf("[Error] Failed to record unban in MySQL: %v", err)
			http.Error(w, `{"error":"failed to save to database"}`, http.StatusInternalServerError)
			return
		}
		log.Printf("[Event] Recorded unban for IP %s in jail %s", cleanIP, jail)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"recorded"}`))
}
