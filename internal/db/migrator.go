package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Migrator handles database schema migrations
type Migrator struct {
	db *sql.DB
	fs embed.FS
}

// NewMigrator creates a new migrator instance
func NewMigrator(database *sql.DB, migrationFS embed.FS) *Migrator {
	return &Migrator{
		db: database,
		fs: migrationFS,
	}
}

// EnsureMigrationTable ensures the schema_migrations table exists
func (m *Migrator) EnsureMigrationTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INT NOT NULL PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
	`
	_, err := m.db.ExecContext(ctx, query)
	return err
}

// GetAppliedVersions returns all versions applied so far
func (m *Migrator) GetAppliedVersions(ctx context.Context) (map[int]bool, error) {
	applied := make(map[int]bool)
	rows, err := m.db.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

// MigrationFile represents a parsed migration file
type MigrationFile struct {
	Version int
	Name    string
	Path    string
}

// Apply runs all pending migrations in order
func (m *Migrator) Apply(ctx context.Context) error {
	if err := m.EnsureMigrationTable(ctx); err != nil {
		return fmt.Errorf("failed to ensure migration table: %w", err)
	}

	applied, err := m.GetAppliedVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	entries, err := m.fs.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to read migrations dir: %w", err)
	}

	var files []MigrationFile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		parts := strings.SplitN(entry.Name(), "_", 2)
		if len(parts) < 2 {
			continue
		}
		ver, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		files = append(files, MigrationFile{
			Version: ver,
			Name:    entry.Name(),
			Path:    filepath.Join("migrations", entry.Name()),
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Version < files[j].Version
	})

	for _, file := range files {
		if applied[file.Version] {
			continue
		}

		log.Printf("[Migration] Applying migration %s (v%d)...", file.Name, file.Version)
		content, err := m.fs.ReadFile(file.Path)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", file.Name, err)
		}

		queries := splitSQLStatements(string(content))
		for _, q := range queries {
			q = strings.TrimSpace(q)
			if q == "" {
				continue
			}
			if _, err := m.db.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("migration %s failed executing query: %s: %w", file.Name, q, err)
			}
		}

		// Record migration
		_, err = m.db.ExecContext(ctx, "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
			file.Version, file.Name, time.Now())
		if err != nil {
			return fmt.Errorf("failed to record migration %s: %w", file.Name, err)
		}
		log.Printf("[Migration] Successfully applied %s", file.Name)
	}

	return nil
}

// splitSQLStatements splits a SQL file content by semicolons while respecting basic formatting
func splitSQLStatements(sqlContent string) []string {
	var statements []string
	var current strings.Builder
	lines := strings.Split(sqlContent, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Ignore comment lines
		if strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		current.WriteString(line)
		current.WriteString("\n")
		if strings.HasSuffix(trimmed, ";") {
			stmt := strings.TrimSpace(current.String())
			if stmt != "" {
				statements = append(statements, stmt)
			}
			current.Reset()
		}
	}

	remaining := strings.TrimSpace(current.String())
	if remaining != "" {
		statements = append(statements, remaining)
	}

	return statements
}
