package db

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type ScheduleRow struct {
	ID         string
	TargetID   string
	Name       string
	CronExpr   string
	Modules    string
	Enabled    bool
	NotifyOn   string
	WebhookURL string
	CreatedBy  string
	LastRunAt  time.Time
	NextRunAt  time.Time
	CreatedAt  time.Time
}

func CreateSchedule(targetID, name, cronExpr, modules, notifyOn, webhookURL, createdBy string) (string, error) {
	d := DB()
	if d == nil {
		return "", fmt.Errorf("database not initialized")
	}

	id := uuid.New().String()
	now := time.Now()
	_, err := d.Exec(
		`INSERT INTO schedules (id, target_id, name, cron_expr, modules, enabled, notify_on, webhook_url, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
		id, targetID, name, cronExpr, modules, notifyOn, webhookURL, createdBy, now,
	)
	if err != nil {
		return "", fmt.Errorf("create schedule: %w", err)
	}
	return id, nil
}

func ListSchedules() ([]ScheduleRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := d.Query("SELECT id, target_id, name, cron_expr, modules, enabled, notify_on, COALESCE(webhook_url,''), COALESCE(created_by,''), created_at FROM schedules WHERE enabled = 1 ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ScheduleRow
	for rows.Next() {
		var r ScheduleRow
		if err := rows.Scan(&r.ID, &r.TargetID, &r.Name, &r.CronExpr, &r.Modules, &r.Enabled, &r.NotifyOn, &r.WebhookURL, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func UpdateSchedule(id, name, cronExpr, modules, notifyOn, webhookURL string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	result, err := d.Exec(
		`UPDATE schedules SET name=?, cron_expr=?, modules=?, notify_on=?, webhook_url=? WHERE id=?`,
		name, cronExpr, modules, notifyOn, webhookURL, id,
	)
	if err != nil {
		return fmt.Errorf("update schedule: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("schedule not found")
	}
	return nil
}

func DeleteSchedule(id string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := d.Exec("DELETE FROM schedules WHERE id = ?", id)
	return err
}
