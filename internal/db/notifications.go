package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type NotificationRow struct {
	ID        string
	UserID    sql.NullString
	ScanID    sql.NullString
	Type      string
	Title     string
	Message   sql.NullString
	Read      bool
	Channel   sql.NullString
	CreatedAt time.Time
}

func CreateNotification(userID, scanID, notifType, title, message, channel string) (string, error) {
	d := DB()
	if d == nil {
		return "", fmt.Errorf("database not initialized")
	}

	id := uuid.New().String()
	now := time.Now()
	uid := sql.NullString{}
	if userID != "" {
		uid = sql.NullString{String: userID, Valid: true}
	}
	sid := sql.NullString{}
	if scanID != "" {
		sid = sql.NullString{String: scanID, Valid: true}
	}
	msg := sql.NullString{}
	if message != "" {
		msg = sql.NullString{String: message, Valid: true}
	}
	ch := sql.NullString{}
	if channel != "" {
		ch = sql.NullString{String: channel, Valid: true}
	}

	_, err := d.Exec(
		`INSERT INTO notifications (id, user_id, scan_id, type, title, message, channel, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, uid, sid, notifType, title, msg, ch, now,
	)
	if err != nil {
		return "", fmt.Errorf("create notification: %w", err)
	}
	return id, nil
}

func ListNotifications(limit int) ([]NotificationRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	if limit <= 0 {
		limit = 50
	}

	rows, err := d.Query(
		`SELECT id, user_id, scan_id, type, title, message, read, channel, created_at
		FROM notifications ORDER BY created_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []NotificationRow
	for rows.Next() {
		var r NotificationRow
		if err := rows.Scan(&r.ID, &r.UserID, &r.ScanID, &r.Type, &r.Title, &r.Message, &r.Read, &r.Channel, &r.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func MarkNotificationRead(id string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := d.Exec("UPDATE notifications SET read = 1 WHERE id = ?", id)
	return err
}

func DeleteNotification(id string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := d.Exec("DELETE FROM notifications WHERE id = ?", id)
	return err
}
