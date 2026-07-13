package db

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type OrganizationRow struct {
	ID          string
	Name        string
	Domain      string
	CreatedBy   string
	CreatedAt   time.Time
	MemberCount int
}

type OrgMemberRow struct {
	ID       string
	OrgID    string
	UserID   string
	Username string
	Role     string
	JoinedAt time.Time
}

func CreateOrganization(name, domain, createdBy string) (string, error) {
	d := DB()
	if d == nil {
		return "", fmt.Errorf("database not initialized")
	}

	id := uuid.New().String()
	now := time.Now()
	_, err := d.Exec(
		`INSERT INTO organizations (id, name, domain, created_by, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, name, domain, createdBy, now,
	)
	if err != nil {
		return "", fmt.Errorf("create organization: %w", err)
	}

	_, err = d.Exec(
		`INSERT INTO organization_members (id, org_id, user_id, role, joined_at) VALUES (?, ?, ?, 'admin', ?)`,
		uuid.New().String(), id, createdBy, now,
	)
	if err != nil {
		return "", fmt.Errorf("add owner to organization: %w", err)
	}

	return id, nil
}

func ListOrganizations() ([]OrganizationRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := d.Query(`
		SELECT o.id, o.name, COALESCE(o.domain,''), o.created_by, o.created_at,
			(SELECT COUNT(*) FROM organization_members WHERE org_id = o.id) as member_count
		FROM organizations o ORDER BY o.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []OrganizationRow
	for rows.Next() {
		var r OrganizationRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Domain, &r.CreatedBy, &r.CreatedAt, &r.MemberCount); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func DeleteOrganization(id string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := d.Exec("DELETE FROM organizations WHERE id = ?", id)
	return err
}

func AddOrgMember(orgID, userID, role string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	id := uuid.New().String()
	now := time.Now()
	_, err := d.Exec(
		`INSERT INTO organization_members (id, org_id, user_id, role, joined_at) VALUES (?, ?, ?, ?, ?)`,
		id, orgID, userID, role, now,
	)
	if err != nil {
		return fmt.Errorf("add organization member: %w", err)
	}
	return nil
}

func RemoveOrgMember(orgID, userID string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := d.Exec("DELETE FROM organization_members WHERE org_id = ? AND user_id = ?", orgID, userID)
	return err
}

func ListOrgMembers(orgID string) ([]OrgMemberRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := d.Query(`
		SELECT om.id, om.org_id, om.user_id, u.username, om.role, om.joined_at
		FROM organization_members om
		JOIN users u ON u.id = om.user_id
		WHERE om.org_id = ?
		ORDER BY om.joined_at
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []OrgMemberRow
	for rows.Next() {
		var r OrgMemberRow
		if err := rows.Scan(&r.ID, &r.OrgID, &r.UserID, &r.Username, &r.Role, &r.JoinedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func GetUserOrgRole(userID, orgID string) (string, error) {
	d := DB()
	if d == nil {
		return "", fmt.Errorf("database not initialized")
	}

	var role string
	err := d.QueryRow(
		"SELECT role FROM organization_members WHERE user_id = ? AND org_id = ?",
		userID, orgID,
	).Scan(&role)
	if err != nil {
		return "", fmt.Errorf("not a member: %w", err)
	}
	return role, nil
}
