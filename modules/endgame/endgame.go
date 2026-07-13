package endgame

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type EndGameModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *EndGameModule) ID() string   { return "endgame" }
func (m *EndGameModule) Name() string { return "EndGame - Destructive Action & Cleanup Module" }
func (m *EndGameModule) Description() string {
	return "Logic bomb detection, database sabotage vectors, backup deletion, self-destruct mechanisms"
}
func (m *EndGameModule) Severity() models.Severity { return models.Critical }

func (m *EndGameModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *EndGameModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkDestructiveEndpoints(ctx, target)...)
	findings = append(findings, m.checkDatabaseEndpoints(ctx, target)...)
	findings = append(findings, m.checkBackupEndpoints(ctx, target)...)
	findings = append(findings, m.checkSelfDestruct(ctx, target)...)

	return findings, nil
}

func (m *EndGameModule) checkDestructiveEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	destructivePaths := []string{
		"/delete-all", "/drop", "/truncate", "/purge",
		"/nuke", "/destroy", "/wipe", "/reset-all",
		"/admin/drop", "/api/purge", "/api/reset",
		"/danger/delete", "/cleanup",
	}

	for _, path := range destructivePaths {
		fullURL := strings.TrimRight(target.URL, "/") + path

		for _, method := range []string{"GET", "POST", "DELETE"} {
			var resp *fanghttp.Response
			var err error

			switch method {
			case "POST":
				resp, err = m.client.Post(fullURL, `{"confirm": true}`)
			case "DELETE":
				resp, err = m.client.Delete(fullURL)
			default:
				resp, err = m.client.Get(fullURL)
			}

			if err != nil {
				continue
			}

			if resp.StatusCode != 404 && resp.StatusCode != 403 {
				for _, check := range []string{"deleted", "dropped", "truncated", "purged",
					"nuked", "destroyed", "wiped", "reset", "success", "confirmed"} {
					if strings.Contains(strings.ToLower(resp.Body), check) {
						findings = append(findings, &models.Finding{
							Title:       fmt.Sprintf("EndGame - Destructive Endpoint (%s on %s)", method, path),
							Severity:    models.Critical,
							Confidence:  models.HighConfidence,
							URL:         fullURL,
							Payload:     fmt.Sprintf("Method: %s", method),
							Evidence:    fmt.Sprintf("Destructive endpoint responds (status: %d, matched: %s)", resp.StatusCode, check),
							Description: fmt.Sprintf("Potentially destructive endpoint %s accessible via %s. Could allow data deletion or system destruction.", path, method),
							Remediation: "Remove destructive endpoints from production. Require multi-factor admin confirmation. Implement soft-delete patterns.",
							CWEID:       "CWE-306",
							ModuleID:    "endgame",
						})
						break
					}
				}
			}
		}
	}

	return findings
}

func (m *EndGameModule) checkDatabaseEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	dbPaths := []string{
		"/phpmyadmin", "/adminer", "/phpPgAdmin",
		"/mysql", "/pma", "/sqladmin",
		"/admin/mysql", "/db", "/database",
		"/api/query", "/api/sql", "/api/db",
		"/redis", "/6379", "/mongo", "/27017",
		"/elasticsearch", "/9200", "/couchdb", "/5984",
	}

	for _, path := range dbPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 404 && resp.StatusCode != 403 {
			for _, check := range []string{"phpmyadmin", "MySQL", "phpPgAdmin", "Adminer",
				"redis", "MongoDB", "Elasticsearch", "CouchDB",
				"database", "query", "result", "table", "select"} {
				if strings.Contains(resp.Body, check) || strings.Contains(resp.Status, check) {
					findings = append(findings, &models.Finding{
						Title:       "EndGame - Database Management Interface",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("Database management interface: %s (matched: %s, status: %d)", path, check, resp.StatusCode),
						Description: fmt.Sprintf("Database management interface accessible at %s. Can execute arbitrary SQL/queries.", path),
						Remediation: "Remove database management tools from production. Restrict by IP and authentication. Use read-only replicas.",
						CWEID:       "CWE-306",
						ModuleID:    "endgame",
					})
					break
				}
			}
		}
	}

	return findings
}

func (m *EndGameModule) checkBackupEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	backupPaths := []string{
		"/backup", "/backups", "/dump", "/export",
		"/db-backup", "/sql-backup", "/database-backup",
		"/backup.sql", "/backup.tar.gz", "/backup.zip",
		"/dump.sql", "/export.sql",
		"/wp-admin/backup", "/admin/backup",
		"/.backup", "/_backup",
	}

	for _, path := range backupPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 && len(resp.Body) > 100 {
			bodyPreview := strings.ToLower(resp.Body[:minEN(len(resp.Body), 500)])

			for _, check := range []string{"create table", "insert into", "drop table",
				"mysql dump", "postgresql dump", "pg_dump",
				"sql server", "backup", "dump", "database",
				"create database"} {
				if strings.Contains(bodyPreview, check) {
					findings = append(findings, &models.Finding{
						Title:       "EndGame - Database Backup Exposed",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("Database backup file accessible (size: %d bytes, matched: %s)", len(resp.Body), check),
						Description: fmt.Sprintf("Database backup exposed at %s. Contains complete database schema and data.", path),
						Remediation: "Store backups outside web root. Use strict access controls. Encrypt backups. Implement backup integrity checking.",
						CWEID:       "CWE-200",
						ModuleID:    "endgame",
					})
					break
				}
			}
		}
	}

	return findings
}

func (m *EndGameModule) checkSelfDestruct(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	selfDestructPaths := []string{
		"/self-destruct", "/shutdown", "/kill", "/die",
		"/panic", "/crash", "/exit", "/emergency-stop",
		"/admin/shutdown", "/api/terminate", "/halt",
	}

	for _, path := range selfDestructPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Post(fullURL, `{"reason":"test"}`)
		if err != nil {
			continue
		}

		if resp.StatusCode != 404 {
			for _, check := range []string{"shutdown", "terminate", "halt", "stopping",
				"emergency", "kill", "crash", "destroy"} {
				if strings.Contains(strings.ToLower(resp.Body), check) || strings.Contains(strings.ToLower(resp.Status), check) {
					findings = append(findings, &models.Finding{
						Title:       "EndGame - Self-Destruct / Kill Switch",
						Severity:    models.Critical,
						Confidence:  models.MediumConfidence,
						URL:         fullURL,
						Payload:     `{"reason":"test"}`,
						Evidence:    fmt.Sprintf("Self-destruct endpoint responds (status: %d, matched: %s)", resp.StatusCode, check),
						Description: "Self-destruct or kill switch endpoint accessible. Could allow system shutdown, process termination, or data destruction.",
						Remediation: "Remove kill switches from production. Require hardware authentication. Implement circuit breaker patterns.",
						CWEID:       "CWE-306",
						ModuleID:    "endgame",
					})
					break
				}
			}
		}
	}

	return findings
}

func minEN(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	engine.GetRegistry().Register(&EndGameModule{})
}
