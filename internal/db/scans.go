package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type ScanRow struct {
	ID          string
	TargetID    string
	Status      string
	Modules     sql.NullString
	Threads     int
	Timeout     int
	Proxy       sql.NullString
	StartedAt   sql.NullTime
	FinishedAt  sql.NullTime
	DurationMs  sql.NullInt64
	Error       sql.NullString
	TriggeredBy sql.NullString
	ScheduleID  sql.NullString
	CreatedAt   time.Time
}

type ScanFilter struct {
	TargetID string
	Status   string
	Limit    int
	Offset   int
}

func CreateScan(targetID string, modules []string, threads, timeout int, proxy, triggeredBy, scheduleID string) (string, error) {
	d := DB()
	if d == nil {
		return "", fmt.Errorf("database not initialized")
	}

	id := uuid.New().String()
	modJSON := "null"
	if len(modules) > 0 {
		modJSON = "[" + joinQuoted(modules) + "]"
	}
	proxyVal := sql.NullString{}
	if proxy != "" {
		proxyVal = sql.NullString{String: proxy, Valid: true}
	}
	tBy := sql.NullString{}
	if triggeredBy != "" {
		tBy = sql.NullString{String: triggeredBy, Valid: true}
	}
	sID := sql.NullString{}
	if scheduleID != "" {
		sID = sql.NullString{String: scheduleID, Valid: true}
	}

	_, err := d.Exec(
		`INSERT INTO scans (id, target_id, status, modules, threads, timeout, proxy, triggered_by, schedule_id, created_at)
		VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)`,
		id, targetID, modJSON, threads, timeout, proxyVal, tBy, sID, time.Now(),
	)
	if err != nil {
		return "", fmt.Errorf("create scan: %w", err)
	}
	return id, nil
}

func UpdateScanStatus(id, status string, errMsg string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	var startedAt sql.NullTime
	err := d.QueryRow("SELECT started_at FROM scans WHERE id = ?", id).Scan(&startedAt)
	if err != nil {
		return fmt.Errorf("scan not found: %w", err)
	}

	now := time.Now()
	errVal := sql.NullString{}
	if errMsg != "" {
		errVal = sql.NullString{String: errMsg, Valid: true}
	}

	if status == "running" && !startedAt.Valid {
		_, err = d.Exec(
			`UPDATE scans SET status = ?, started_at = ?, error = ? WHERE id = ?`,
			status, now, errVal, id,
		)
		return err
	}

	var durationMs int
	if startedAt.Valid && (status == "completed" || status == "failed" || status == "cancelled") {
		durationMs = int(now.Sub(startedAt.Time).Milliseconds())
	}

	_, err = d.Exec(
		`UPDATE scans SET status = ?, finished_at = ?, duration_ms = ?, error = ? WHERE id = ?`,
		status, now, durationMs, errVal, id,
	)
	return err
}

func QueryScans(filter ScanFilter) ([]ScanRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	query := "SELECT id, target_id, status, modules, threads, timeout, proxy, started_at, finished_at, duration_ms, error, triggered_by, schedule_id, created_at FROM scans"
	var conditions []string
	var args []any

	if filter.TargetID != "" {
		conditions = append(conditions, "target_id = ?")
		args = append(args, filter.TargetID)
	}
	if filter.Status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, filter.Status)
	}
	if len(conditions) > 0 {
		query += " WHERE " + joinConditions(conditions, " AND ")
	}
	query += " ORDER BY created_at DESC"

	if filter.Limit <= 0 {
		filter.Limit = 20
	}
	query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ScanRow
	for rows.Next() {
		var r ScanRow
		err := rows.Scan(&r.ID, &r.TargetID, &r.Status, &r.Modules,
			&r.Threads, &r.Timeout, &r.Proxy, &r.StartedAt, &r.FinishedAt,
			&r.DurationMs, &r.Error, &r.TriggeredBy, &r.ScheduleID, &r.CreatedAt)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func GetScan(id string) (*ScanRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var r ScanRow
	err := d.QueryRow(
		`SELECT id, target_id, status, modules, threads, timeout, proxy, started_at, finished_at, duration_ms, error, triggered_by, schedule_id, created_at FROM scans WHERE id = ?`, id,
	).Scan(&r.ID, &r.TargetID, &r.Status, &r.Modules,
		&r.Threads, &r.Timeout, &r.Proxy, &r.StartedAt, &r.FinishedAt,
		&r.DurationMs, &r.Error, &r.TriggeredBy, &r.ScheduleID, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func joinConditions(conds []string, sep string) string {
	result := conds[0]
	for _, c := range conds[1:] {
		result += sep + c
	}
	return result
}

func GetRecentScans(limit int) ([]ScanRow, error) {
	if limit <= 0 {
		limit = 10
	}
	return QueryScans(ScanFilter{Limit: limit})
}

func joinQuoted(items []string) string {
	result := ""
	for i, item := range items {
		if i > 0 {
			result += ","
		}
		result += "'" + item + "'"
	}
	return result
}
