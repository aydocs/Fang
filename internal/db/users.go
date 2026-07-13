package db

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserRow struct {
	ID        string
	Username  string
	Email     string
	Password  string
	Role      string
	APIKey    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func CreateUser(username, email, password, role string) (string, error) {
	d := DB()
	if d == nil {
		return "", fmt.Errorf("database not initialized")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}

	id := uuid.New().String()
	now := time.Now()
	_, err = d.Exec(
		`INSERT INTO users (id, username, email, password, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, username, email, string(hash), role, now, now,
	)
	if err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}
	return id, nil
}

func AuthenticateUser(username, password string) (*UserRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var r UserRow
	err := d.QueryRow(
		"SELECT id, username, email, password, role, COALESCE(api_key,''), created_at, updated_at FROM users WHERE username = ? OR email = ?",
		username, username,
	).Scan(&r.ID, &r.Username, &r.Email, &r.Password, &r.Role, &r.APIKey, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(r.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	return &r, nil
}

func AuthenticateByAPIKey(apiKey string) (*UserRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var r UserRow
	err := d.QueryRow(
		"SELECT id, username, email, password, role, api_key, created_at, updated_at FROM users WHERE api_key = ?",
		apiKey,
	).Scan(&r.ID, &r.Username, &r.Email, &r.Password, &r.Role, &r.APIKey, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("invalid API key")
	}
	return &r, nil
}

func ListUsers() ([]UserRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := d.Query("SELECT id, username, email, password, role, COALESCE(api_key,''), created_at, updated_at FROM users ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []UserRow
	for rows.Next() {
		var r UserRow
		if err := rows.Scan(&r.ID, &r.Username, &r.Email, &r.Password, &r.Role, &r.APIKey, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
