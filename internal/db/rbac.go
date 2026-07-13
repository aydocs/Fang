package db

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type AuditEntry struct {
	ID        string
	UserID    string
	Username  string
	OrgID     string
	Action    string
	Resource  string
	Details   string
	CreatedAt time.Time
}

func roleLevel(role string) int {
	switch role {
	case "admin":
		return 3
	case "member":
		return 2
	case "viewer":
		return 1
	default:
		return 0
	}
}

func RequireRole(userID, orgID, minRole string) bool {
	d := DB()
	if d == nil {
		return false
	}

	var role string
	err := d.QueryRow(
		"SELECT role FROM organization_members WHERE user_id = ? AND org_id = ?",
		userID, orgID,
	).Scan(&role)
	if err != nil {
		return false
	}

	return roleLevel(role) >= roleLevel(minRole)
}

func GetUserPermissions(userID string) ([]string, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := d.Query(`
		SELECT DISTINCT om.role, o.name
		FROM organization_members om
		JOIN organizations o ON o.id = om.org_id
		WHERE om.user_id = ?
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var role, orgName string
		if err := rows.Scan(&role, &orgName); err != nil {
			return nil, err
		}
		perms = append(perms, fmt.Sprintf("%s:%s", orgName, role))
	}
	return perms, rows.Err()
}

func LogAuditEvent(userID, orgID, action, resource, details string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	id := uuid.New().String()
	now := time.Now()
	_, err := d.Exec(
		`INSERT INTO audit_log (id, user_id, org_id, action, resource, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, userID, orgID, action, resource, details, now,
	)
	if err != nil {
		return fmt.Errorf("log audit event: %w", err)
	}
	return nil
}

func QueryAuditLog(orgID string, limit int) ([]AuditEntry, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	if limit <= 0 {
		limit = 50
	}

	rows, err := d.Query(`
		SELECT al.id, al.user_id, COALESCE(u.username,''), al.org_id, al.action, COALESCE(al.resource,''), COALESCE(al.details,''), al.created_at
		FROM audit_log al
		LEFT JOIN users u ON u.id = al.user_id
		WHERE al.org_id = ?
		ORDER BY al.created_at DESC LIMIT ?
	`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AuditEntry
	for rows.Next() {
		var r AuditEntry
		if err := rows.Scan(&r.ID, &r.UserID, &r.Username, &r.OrgID, &r.Action, &r.Resource, &r.Details, &r.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
