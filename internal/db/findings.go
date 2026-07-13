package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/aydocs/fang/pkg/models"
	"github.com/google/uuid"
)

type FindingRow struct {
	ID              string
	ScanID          string
	TargetID        string
	ModuleID        string
	Title           string
	Severity        string
	Confidence      string
	CWEID           sql.NullString
	OWASPCategory   sql.NullString
	CVSS            sql.NullFloat64
	URL             sql.NullString
	Parameter       sql.NullString
	Payload         sql.NullString
	Evidence        sql.NullString
	Description     sql.NullString
	Remediation     sql.NullString
	Request         sql.NullString
	Response        sql.NullString
	Extra           sql.NullString
	IsFalsePositive bool
	CreatedAt       time.Time
}

type FindingFilter struct {
	ScanID   string
	TargetID string
	ModuleID string
	Severity string
	Search   string
	Limit    int
	Offset   int
}

func InsertFindings(tx *sql.Tx, scanID, targetID string, findings []*models.Finding) error {
	stmt, err := tx.Prepare(`
		INSERT INTO findings (id, scan_id, target_id, module_id, title, severity, confidence,
			cwe_id, owasp_category, cvss, url, parameter, payload, evidence, description,
			remediation, request, response, extra, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert findings: %w", err)
	}
	defer stmt.Close()

	for _, f := range findings {
		sev := f.Severity.String()
		conf := f.Confidence.String()
		now := time.Now()

		_, err := stmt.Exec(
			uuid.New().String(), scanID, targetID, f.ModuleID, f.Title, sev, conf,
			nullString(f.CWEID), nullString(f.OWASPCategory), nullFloat(f.CVSS),
			nullString(f.URL), nullString(f.Parameter), nullString(f.Payload),
			nullString(f.Evidence), nullString(f.Description), nullString(f.Remediation),
			nullString(f.Request), nullString(f.Response), nullString(""),
			now,
		)
		if err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
	}
	return nil
}

func QueryFindings(filter FindingFilter) ([]FindingRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var conditions []string
	var args []any

	if filter.ScanID != "" {
		conditions = append(conditions, "scan_id = ?")
		args = append(args, filter.ScanID)
	}
	if filter.TargetID != "" {
		conditions = append(conditions, "target_id = ?")
		args = append(args, filter.TargetID)
	}
	if filter.ModuleID != "" {
		conditions = append(conditions, "module_id = ?")
		args = append(args, filter.ModuleID)
	}
	if filter.Severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, strings.ToUpper(filter.Severity))
	}
	if filter.Search != "" {
		conditions = append(conditions, "(title LIKE ? OR url LIKE ? OR evidence LIKE ?)")
		s := "%" + filter.Search + "%"
		args = append(args, s, s, s)
	}

	query := "SELECT id, scan_id, target_id, module_id, title, severity, confidence, cwe_id, owasp_category, cvss, url, parameter, payload, evidence, description, remediation, request, response, extra, is_false_positive, created_at FROM findings"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY created_at DESC"

	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()

	var result []FindingRow
	for rows.Next() {
		var r FindingRow
		err := rows.Scan(&r.ID, &r.ScanID, &r.TargetID, &r.ModuleID,
			&r.Title, &r.Severity, &r.Confidence,
			&r.CWEID, &r.OWASPCategory, &r.CVSS,
			&r.URL, &r.Parameter, &r.Payload, &r.Evidence,
			&r.Description, &r.Remediation,
			&r.Request, &r.Response, &r.Extra,
			&r.IsFalsePositive, &r.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func CountFindings(filter FindingFilter) (int, error) {
	d := DB()
	if d == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	var conditions []string
	var args []any
	if filter.ScanID != "" {
		conditions = append(conditions, "scan_id = ?")
		args = append(args, filter.ScanID)
	}
	if filter.Severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, strings.ToUpper(filter.Severity))
	}

	query := "SELECT COUNT(*) FROM findings"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	var count int
	if err := d.QueryRow(query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

type SeverityStat struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type ModuleStat struct {
	ModuleID string `json:"module_id"`
	Count    int    `json:"count"`
}

func GetSeverityStats() (map[string]int, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := d.Query("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := map[string]int{}
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		stats[sev] = count
	}
	return stats, rows.Err()
}

func GetSeverityBreakdown() ([]SeverityStat, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := d.Query("SELECT severity, COUNT(*) FROM findings GROUP BY severity ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 WHEN 'INFO' THEN 4 ELSE 5 END")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []SeverityStat
	for rows.Next() {
		var s SeverityStat
		if err := rows.Scan(&s.Severity, &s.Count); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, rows.Err()
}

func GetModuleStats() ([]ModuleStat, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := d.Query("SELECT module_id, COUNT(*) FROM findings GROUP BY module_id ORDER BY COUNT(*) DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []ModuleStat
	for rows.Next() {
		var s ModuleStat
		if err := rows.Scan(&s.ModuleID, &s.Count); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, rows.Err()
}

func GetFinding(id string) (*FindingRow, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var r FindingRow
	err := d.QueryRow(
		`SELECT id, scan_id, target_id, module_id, title, severity, confidence,
		cwe_id, owasp_category, cvss, url, parameter, payload, evidence,
		description, remediation, request, response, extra,
		is_false_positive, created_at
		FROM findings WHERE id = ?`, id,
	).Scan(&r.ID, &r.ScanID, &r.TargetID, &r.ModuleID,
		&r.Title, &r.Severity, &r.Confidence,
		&r.CWEID, &r.OWASPCategory, &r.CVSS,
		&r.URL, &r.Parameter, &r.Payload, &r.Evidence,
		&r.Description, &r.Remediation,
		&r.Request, &r.Response, &r.Extra,
		&r.IsFalsePositive, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func UpdateFinding(id string, isFalsePositive bool, severity, notes string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	result, err := d.Exec(
		"UPDATE findings SET is_false_positive=?, severity=?, extra=? WHERE id=?",
		isFalsePositive, severity, notes, id,
	)
	if err != nil {
		return fmt.Errorf("update finding: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("finding not found")
	}
	return nil
}

func DeleteFinding(id string) error {
	d := DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := d.Exec("DELETE FROM findings WHERE id = ?", id)
	return err
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullFloat(f *float64) sql.NullFloat64 {
	if f == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: *f, Valid: true}
}
