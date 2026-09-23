-- Migration 000001: Initial schema for paloma-fw
-- Compatible with MySQL 8.0+ and MySQL HeatWave on OCI

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INT NOT NULL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type ENUM('ban', 'unban', 'manual_unban') NOT NULL,
    ip VARCHAR(45) NOT NULL,
    jail VARCHAR(64) NOT NULL DEFAULT 'traefik-401',
    failures INT NOT NULL DEFAULT 0,
    duration_seconds INT NOT NULL DEFAULT 172800,
    reason VARCHAR(255) DEFAULT 'Excessive 401 Unauthorized errors',
    country_code VARCHAR(8) DEFAULT NULL,
    country_name VARCHAR(64) DEFAULT NULL,
    asn VARCHAR(128) DEFAULT NULL,
    actor VARCHAR(64) DEFAULT 'fail2ban',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_events_ip (ip),
    INDEX idx_events_created (created_at DESC),
    INDEX idx_events_type (event_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS active_bans (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    jail VARCHAR(64) NOT NULL DEFAULT 'traefik-401',
    failures INT NOT NULL DEFAULT 5,
    banned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    status ENUM('active', 'unbanned', 'expired') NOT NULL DEFAULT 'active',
    unbanned_at TIMESTAMP NULL DEFAULT NULL,
    unbanned_by VARCHAR(64) NULL DEFAULT NULL,
    notes TEXT NULL,
    INDEX idx_bans_status (status),
    INDEX idx_bans_expires (expires_at),
    INDEX idx_bans_banned_at (banned_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target_ip VARCHAR(45) NULL,
    details TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_created (created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
