package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Config holds MySQL HeatWave connection settings
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
}

// Store wraps the SQL database pool and data access methods
type Store struct {
	db *sql.DB
}

// NewStore initializes a connection pool to MySQL HeatWave
func NewStore(cfg Config) (*Store, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4&loc=UTC&timeout=10s&readTimeout=10s&writeTimeout=10s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Database)

	database, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database handle: %w", err)
	}

	// Optimize connection pooling for lightweight low-overhead operation
	database.SetMaxOpenConns(20)
	database.SetMaxIdleConns(5)
	database.SetConnMaxLifetime(5 * time.Minute)
	database.SetConnMaxIdleTime(2 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := database.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping MySQL HeatWave (%s:%d): %w", cfg.Host, cfg.Port, err)
	}

	return &Store{db: database}, nil
}

// DB returns the underlying sql.DB instance
func (s *Store) DB() *sql.DB {
	return s.db
}

// Close closes the database connection pool
func (s *Store) Close() error {
	return s.db.Close()
}

// Models
type SecurityEvent struct {
	ID              int64     `json:"id"`
	EventType       string    `json:"event_type"` // ban, unban, manual_unban
	IP              string    `json:"ip"`
	Jail            string    `json:"jail"`
	Failures        int       `json:"failures"`
	DurationSeconds int       `json:"duration_seconds"`
	Reason          string    `json:"reason"`
	CountryCode     *string   `json:"country_code,omitempty"`
	CountryName     *string   `json:"country_name,omitempty"`
	ASN             *string   `json:"asn,omitempty"`
	Actor           string    `json:"actor"`
	CreatedAt       time.Time `json:"created_at"`
}

type ActiveBan struct {
	ID         int64      `json:"id"`
	IP         string     `json:"ip"`
	Jail       string     `json:"jail"`
	Failures   int        `json:"failures"`
	BannedAt   time.Time  `json:"banned_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Status     string     `json:"status"` // active, unbanned, expired
	UnbannedAt *time.Time `json:"unbanned_at,omitempty"`
	UnbannedBy *string    `json:"unbanned_by,omitempty"`
	Notes      *string    `json:"notes,omitempty"`
}

type AuditLog struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	TargetIP  *string   `json:"target_ip,omitempty"`
	Details   *string   `json:"details,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type DashboardMetrics struct {
	ActiveBansCount int   `json:"active_bans_count"`
	BansLast24h     int   `json:"bans_last_24h"`
	TotalBansAllTime int  `json:"total_bans_all_time"`
	TotalUnbans     int   `json:"total_unbans"`
	TopAttackingIPs []TopIP `json:"top_attacking_ips"`
}

type TopIP struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// RecordBan inserts or updates an active ban and registers a security event
func (s *Store) RecordBan(ctx context.Context, ip, jail string, failures, durationSeconds int, reason, actor string) error {
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(durationSeconds) * time.Second)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Insert into security_events
	eventQuery := `
		INSERT INTO security_events (event_type, ip, jail, failures, duration_seconds, reason, actor, created_at)
		VALUES ('ban', ?, ?, ?, ?, ?, ?, ?)
	`
	if _, err := tx.ExecContext(ctx, eventQuery, ip, jail, failures, durationSeconds, reason, actor, now); err != nil {
		return fmt.Errorf("failed to insert security_event: %w", err)
	}

	// 2. Upsert into active_bans
	banQuery := `
		INSERT INTO active_bans (ip, jail, failures, banned_at, expires_at, status, unbanned_at, unbanned_by)
		VALUES (?, ?, ?, ?, ?, 'active', NULL, NULL)
		ON DUPLICATE KEY UPDATE
			jail = VALUES(jail),
			failures = VALUES(failures),
			banned_at = VALUES(banned_at),
			expires_at = VALUES(expires_at),
			status = 'active',
			unbanned_at = NULL,
			unbanned_by = NULL
	`
	if _, err := tx.ExecContext(ctx, banQuery, ip, jail, failures, now, expiresAt); err != nil {
		return fmt.Errorf("failed to upsert active_bans: %w", err)
	}

	return tx.Commit()
}

// EnsureActiveBan verifies if an IP is already recorded as active, and if not, records it
func (s *Store) EnsureActiveBan(ctx context.Context, ip, jail string, failures, durationSeconds int, reason, actor string) error {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM active_bans WHERE ip = ? AND status = 'active'", ip).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return s.RecordBan(ctx, ip, jail, failures, durationSeconds, reason, actor)
	}
	return nil
}

// RecordUnban marks an active ban as unbanned and records an unban event
func (s *Store) RecordUnban(ctx context.Context, ip, jail, actor, notes string, manual bool) error {
	now := time.Now().UTC()
	eventType := "unban"
	if manual {
		eventType = "manual_unban"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Insert into security_events
	eventQuery := `
		INSERT INTO security_events (event_type, ip, jail, reason, actor, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	reason := "Unbanned via dashboard"
	if !manual {
		reason = "Automatic expiration by Fail2ban"
	}
	if _, err := tx.ExecContext(ctx, eventQuery, eventType, ip, jail, reason, actor, now); err != nil {
		return fmt.Errorf("failed to record unban event: %w", err)
	}

	// 2. Update active_bans
	banQuery := `
		UPDATE active_bans
		SET status = 'unbanned', unbanned_at = ?, unbanned_by = ?, notes = ?
		WHERE ip = ?
	`
	if _, err := tx.ExecContext(ctx, banQuery, now, actor, notes, ip); err != nil {
		return fmt.Errorf("failed to update active_bans: %w", err)
	}

	return tx.Commit()
}

// ListActiveBans returns all currently active bans
func (s *Store) ListActiveBans(ctx context.Context) ([]ActiveBan, error) {
	query := `
		SELECT id, ip, jail, failures, banned_at, expires_at, status, unbanned_at, unbanned_by, notes
		FROM active_bans
		WHERE status = 'active'
		ORDER BY banned_at DESC
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bans []ActiveBan
	for rows.Next() {
		var b ActiveBan
		if err := rows.Scan(&b.ID, &b.IP, &b.Jail, &b.Failures, &b.BannedAt, &b.ExpiresAt, &b.Status, &b.UnbannedAt, &b.UnbannedBy, &b.Notes); err != nil {
			return nil, err
		}
		bans = append(bans, b)
	}
	return bans, rows.Err()
}

// ListEvents returns paginated security events with optional search filtering
func (s *Store) ListEvents(ctx context.Context, page, limit int, search, eventType string) ([]SecurityEvent, int, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 50
	}
	offset := (page - 1) * limit

	whereClauses := []string{"1=1"}
	var args []interface{}

	if search != "" {
		whereClauses = append(whereClauses, "ip LIKE ?")
		args = append(args, "%"+search+"%")
	}
	if eventType != "" {
		whereClauses = append(whereClauses, "event_type = ?")
		args = append(args, eventType)
	}

	whereSQL := ""
	for _, c := range whereClauses {
		whereSQL += " AND " + c
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM security_events WHERE 1=1 %s", whereSQL)
	var total int
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Select rows
	dataQuery := fmt.Sprintf(`
		SELECT id, event_type, ip, jail, failures, duration_seconds, reason, country_code, country_name, asn, actor, created_at
		FROM security_events
		WHERE 1=1 %s
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, whereSQL)

	queryArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, dataQuery, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		var e SecurityEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.IP, &e.Jail, &e.Failures, &e.DurationSeconds, &e.Reason,
			&e.CountryCode, &e.CountryName, &e.ASN, &e.Actor, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		events = append(events, e)
	}

	return events, total, rows.Err()
}

// GetMetrics aggregates operational numbers for the dashboard
func (s *Store) GetMetrics(ctx context.Context) (*DashboardMetrics, error) {
	metrics := &DashboardMetrics{}

	// Active bans count
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM active_bans WHERE status = 'active'").Scan(&metrics.ActiveBansCount)

	// Bans in last 24h
	twentyFourHoursAgo := time.Now().UTC().Add(-24 * time.Hour)
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_events WHERE event_type = 'ban' AND created_at >= ?", twentyFourHoursAgo).Scan(&metrics.BansLast24h)

	// Total bans all time
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_events WHERE event_type = 'ban'").Scan(&metrics.TotalBansAllTime)

	// Total unbans
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_events WHERE event_type IN ('unban', 'manual_unban')").Scan(&metrics.TotalUnbans)

	// Top attacking IPs
	rows, err := s.db.QueryContext(ctx, `
		SELECT ip, COUNT(*) as cnt
		FROM security_events
		WHERE event_type = 'ban'
		GROUP BY ip
		ORDER BY cnt DESC
		LIMIT 5
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var tip TopIP
			if err := rows.Scan(&tip.IP, &tip.Count); err == nil {
				metrics.TopAttackingIPs = append(metrics.TopAttackingIPs, tip)
			}
		}
	}

	return metrics, nil
}

// RecordAudit registers an administrative audit log entry
func (s *Store) RecordAudit(ctx context.Context, username, action string, targetIP *string, details *string) error {
	query := `
		INSERT INTO audit_logs (username, action, target_ip, details, created_at)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := s.db.ExecContext(ctx, query, username, action, targetIP, details, time.Now().UTC())
	return err
}
