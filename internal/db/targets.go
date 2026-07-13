package db

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type TargetRow struct {
	ID        string
	URL       string
	Domain    string
	Name      string
	Tags      string
	CreatedBy string
	CreatedAt time.Time
}

func CreateTarget(url, domain, name, tags, createdBy string) (string, error) {
	d := DB()
	if d == nil {
		return "", fmt.Errorf("database not initialized")
	}

	id := uuid.New().String()
	_, err := d.Exec(
		`INSERT INTO targets (id, url, domain, name, tags, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, url, domain, name, tags, createdBy, time.Now(),
	)
	if err != nil {
		return "", fmt.Errorf("create target: %w", err)
	}
	return id, nil
}

func ListTargets() ([]TargetRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := d.Query("SELECT id, url, domain, name, tags, created_by, created_at FROM targets ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []TargetRow
	for rows.Next() {
		var r TargetRow
		if err := rows.Scan(&r.ID, &r.URL, &r.Domain, &r.Name, &r.Tags, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func GetTarget(id string) (*TargetRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var r TargetRow
	err := d.QueryRow(
		"SELECT id, url, domain, name, tags, created_by, created_at FROM targets WHERE id = ?", id,
	).Scan(&r.ID, &r.URL, &r.Domain, &r.Name, &r.Tags, &r.CreatedBy, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func UpdateTarget(id, url, domain, name, tags string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	result, err := d.Exec(
		"UPDATE targets SET url=?, domain=?, name=?, tags=? WHERE id=?",
		url, domain, name, tags, id,
	)
	if err != nil {
		return fmt.Errorf("update target: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("target not found")
	}
	return nil
}

func DeleteTarget(id string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := d.Exec("DELETE FROM targets WHERE id = ?", id)
	return err
}
