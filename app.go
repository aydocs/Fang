package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/aydocs/fang/internal/bugbounty"
	"github.com/aydocs/fang/internal/config"
	"github.com/aydocs/fang/internal/db"
	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/internal/evasion"
	"github.com/aydocs/fang/internal/i18n"
	"github.com/aydocs/fang/internal/integration"
	"github.com/aydocs/fang/internal/plugin"
	"github.com/aydocs/fang/internal/report"
	"github.com/aydocs/fang/internal/scheduler"
	"github.com/aydocs/fang/internal/workflow"

	_ "github.com/aydocs/fang/internal/i18n/locales"
	"github.com/aydocs/fang/pkg/models"
	"github.com/google/uuid"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	ctx           context.Context
	engine        *engine.Engine
	scheduler     *scheduler.Scheduler
	workflowEng   *workflow.Engine
	mu            sync.Mutex
	activeScan    string
	cancelScan    context.CancelFunc
	loginAttempts map[string]time.Time
	currentUserID string

	pluginMgr  *plugin.Manager
	evasionEng *evasion.Engine
	siemCfg    *integration.SIEMConfig
	lang       string
}

type ModuleInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type ScanRequest struct {
	TargetURL string   `json:"target_url"`
	Modules   []string `json:"modules,omitempty"`
	Threads   int      `json:"threads,omitempty"`
	Timeout   int      `json:"timeout,omitempty"`
}

type ScanProgress struct {
	ScanID  string `json:"scan_id"`
	Status  string `json:"status"`
	Current int    `json:"current"`
	Total   int    `json:"total"`
	Module  string `json:"module"`
	Message string `json:"message"`
}

type ScanStats struct {
	TotalScans    int `json:"total_scans"`
	TotalFindings int `json:"total_findings"`
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
}

type ScheduleInput struct {
	TargetID   string `json:"target_id"`
	Name       string `json:"name"`
	CronExpr   string `json:"cron_expr"`
	Modules    string `json:"modules"`
	NotifyOn   string `json:"notify_on"`
	WebhookURL string `json:"webhook_url"`
}

func NewApp() *App {
	return &App{
		loginAttempts: make(map[string]time.Time),
	}
}

func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx

	dbPath := filepath.Join(os.Getenv("HOME"), ".fang", "data", "fang.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	dbCfg := db.DefaultConfig()
	dbCfg.Path = dbPath

	if _, err := db.Open(dbCfg); err != nil {
		fmt.Printf("[fang] db init: %v\n", err)
	}

	if _, err := config.Load(); err != nil {
		fmt.Printf("[fang] config load: %v\n", err)
	}

	ensureDefaultUser()

	a.scheduler = scheduler.New()
	if err := a.scheduler.Start(); err != nil {
		fmt.Printf("[fang] scheduler: %v\n", err)
	}

	engCfg := engine.NewConfig()
	a.engine = engine.New(engCfg)

	a.workflowEng = workflow.NewEngine()
	wfPath := filepath.Join(os.Getenv("HOME"), ".fang", "config", "workflows.json")
	if _, err := workflow.LoadWorkflows(wfPath); err == nil {
		wfs, err := workflow.LoadWorkflows(wfPath)
		if err == nil {
			for _, w := range wfs {
				a.workflowEng.Add(w)
			}
		}
	}

	pluginDir := filepath.Join(os.Getenv("HOME"), ".fang", "plugins")
	a.pluginMgr = plugin.NewManager(pluginDir)
	if err := a.pluginMgr.LoadAll(); err != nil {
		fmt.Printf("[fang] plugin load: %v\n", err)
	}

	a.evasionEng = evasion.New(nil)

	siemCfgPath := filepath.Join(os.Getenv("HOME"), ".fang", "config", "siem.json")
	if data, err := os.ReadFile(siemCfgPath); err == nil {
		var sc integration.SIEMConfig
		if err := json.Unmarshal(data, &sc); err == nil {
			a.siemCfg = &sc
		}
	}
}

func (a *App) Shutdown(ctx context.Context) {
	if a.scheduler != nil {
		a.scheduler.Stop()
	}
	db.Close()
}

func (a *App) RunScan(targetURL string, modules []string) (string, error) {
	cfgOptions := []engine.Option{}
	if len(modules) > 0 {
		cfgOptions = append(cfgOptions, engine.WithModules(modules...))
	}
	cfg := engine.NewConfig(cfgOptions...)

	targetID, err := db.CreateTarget(targetURL, "", "", "", "")
	if err != nil {
		return "", fmt.Errorf("create target: %w", err)
	}

	scanID, err := db.CreateScan(targetID, modules, cfg.Threads, int(cfg.Timeout.Seconds()), "", "gui", "")
	if err != nil {
		return "", fmt.Errorf("create scan: %w", err)
	}

	db.UpdateScanStatus(scanID, "running", "")

	scanCtx, cancel := context.WithTimeout(a.ctx, 30*time.Minute)
	defer cancel()

	eng := engine.New(cfg)
	result, err := eng.Run(scanCtx, targetURL)
	if err != nil {
		db.UpdateScanStatus(scanID, "failed", err.Error())
		return scanID, fmt.Errorf("scan: %w", err)
	}

	if len(result.Findings) > 0 {
		tx, _ := db.BeginTx()
		if tx != nil {
			db.InsertFindings(tx, scanID, targetID, result.Findings)
			tx.Commit()
		}
	}

	db.UpdateScanStatus(scanID, "completed", "")
	return scanID, nil
}

func (a *App) RunScanAsync(targetURL string, modules []string) string {
	a.mu.Lock()
	if a.activeScan != "" {
		a.mu.Unlock()
		runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
			Type:    "error",
			Title:   "Scan in Progress",
			Message: "A scan is already running. Please wait for it to complete or cancel it.",
		})
		return ""
	}
	a.mu.Unlock()

	cfgOptions := []engine.Option{}
	if len(modules) > 0 {
		cfgOptions = append(cfgOptions, engine.WithModules(modules...))
	}
	cfg := engine.NewConfig(cfgOptions...)

	targetID, err := db.CreateTarget(targetURL, "", "", "", "")
	if err != nil {
		runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
			Type:    "error",
			Title:   "Error",
			Message: fmt.Sprintf("Failed to create target: %v", err),
		})
		return ""
	}

	scanID, err := db.CreateScan(targetID, modules, cfg.Threads, int(cfg.Timeout.Seconds()), "", "gui", "")
	if err != nil {
		runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
			Type:    "error",
			Title:   "Error",
			Message: fmt.Sprintf("Failed to create scan: %v", err),
		})
		return ""
	}

	a.mu.Lock()
	a.activeScan = scanID
	scanCtx, cancel := context.WithCancel(a.ctx)
	a.cancelScan = cancel
	a.mu.Unlock()

	db.UpdateScanStatus(scanID, "running", "")

	go func() {
		defer func() {
			a.mu.Lock()
			a.activeScan = ""
			a.cancelScan = nil
			a.mu.Unlock()
		}()

		runtime.EventsEmit(a.ctx, "scan:started", ScanProgress{
			ScanID: scanID,
			Status: "running",
			Module: "Initializing...",
		})

		eng := engine.New(cfg)

		result, err := eng.Run(scanCtx, targetURL)
		if err != nil {
			db.UpdateScanStatus(scanID, "failed", err.Error())
			db.CreateNotification("", scanID, "scan_error", "Scan Failed",
				fmt.Sprintf("Scan on %s failed: %v", targetURL, err), "in_app")
			runtime.EventsEmit(a.ctx, "scan:error", ScanProgress{
				ScanID:  scanID,
				Status:  "failed",
				Message: err.Error(),
			})
			return
		}

		if len(result.Findings) > 0 {
			tx, txErr := db.BeginTx()
			if txErr == nil {
				if insErr := db.InsertFindings(tx, scanID, targetID, result.Findings); insErr != nil {
					tx.Rollback()
				} else {
					tx.Commit()
				}
			}
		}

		db.UpdateScanStatus(scanID, "completed", "")
		db.CreateNotification("", scanID, "scan_complete", "Scan Completed",
			fmt.Sprintf("Found %d findings on %s", len(result.Findings), targetURL), "in_app")

		runtime.EventsEmit(a.ctx, "scan:completed", ScanProgress{
			ScanID:  scanID,
			Status:  "completed",
			Current: 1,
			Total:   1,
			Message: fmt.Sprintf("Completed with %d findings", len(result.Findings)),
		})
	}()

	return scanID
}

func (a *App) CancelScan() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancelScan != nil {
		a.cancelScan()
	}
}

func (a *App) GetActiveScan() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.activeScan
}

func (a *App) GetTargets() ([]db.TargetRow, error) {
	return db.ListTargets()
}

func (a *App) CreateTarget(url string) (string, error) {
	return db.CreateTarget(url, "", "", "", "")
}

func (a *App) DeleteTarget(id string) error {
	return db.DeleteTarget(id)
}

func (a *App) GetScans() ([]db.ScanRow, error) {
	return db.QueryScans(db.ScanFilter{Limit: 100})
}

func (a *App) GetScan(scanID string) (*db.ScanRow, error) {
	return db.GetScan(scanID)
}

func (a *App) GetScanFindings(scanID string) ([]db.FindingRow, error) {
	return db.QueryFindings(db.FindingFilter{ScanID: scanID, Limit: 500})
}

func (a *App) GetAllFindings(limit, offset int) ([]db.FindingRow, error) {
	return db.QueryFindings(db.FindingFilter{Limit: limit, Offset: offset})
}

func (a *App) GetSeverityStats() ([]db.SeverityStat, error) {
	return db.GetSeverityBreakdown()
}

func (a *App) GetModuleStats() ([]db.ModuleStat, error) {
	return db.GetModuleStats()
}

func (a *App) GetNotifications() ([]db.NotificationRow, error) {
	return db.ListNotifications(50)
}

func (a *App) MarkNotificationRead(id string) error {
	return db.MarkNotificationRead(id)
}

func (a *App) DeleteNotification(id string) error {
	return db.DeleteNotification(id)
}

func (a *App) ListModules() []ModuleInfo {
	modules := engine.GetRegistry().List()
	info := make([]ModuleInfo, 0, len(modules))
	for _, m := range modules {
		info = append(info, ModuleInfo{
			ID:          m.ID(),
			Name:        m.Name(),
			Description: m.Description(),
			Severity:    m.Severity().String(),
		})
	}
	return info
}

func (a *App) GetStats() ScanStats {
	stats := ScanStats{}
	severity, err := db.GetSeverityBreakdown()
	if err == nil {
		for _, s := range severity {
			switch s.Severity {
			case "CRITICAL":
				stats.CriticalCount = s.Count
			case "HIGH":
				stats.HighCount = s.Count
			case "MEDIUM":
				stats.MediumCount = s.Count
			case "LOW":
				stats.LowCount = s.Count
			}
			stats.TotalFindings += s.Count
		}
	}
	scans, err := db.QueryScans(db.ScanFilter{Limit: 10000})
	if err == nil {
		stats.TotalScans = len(scans)
	}
	return stats
}

func (a *App) GenerateReport(scanID, format string) (string, error) {
	scan, err := db.GetScan(scanID)
	if err != nil {
		return "", fmt.Errorf("scan not found: %w", err)
	}

	findings, err := db.QueryFindings(db.FindingFilter{ScanID: scanID, Limit: 10000})
	if err != nil {
		return "", fmt.Errorf("query findings: %w", err)
	}

	target, err := db.GetTarget(scan.TargetID)
	if err != nil {
		return "", fmt.Errorf("target not found: %w", err)
	}

	result := &models.ScanResult{
		Target:   target.URL,
		Findings: make([]*models.Finding, len(findings)),
	}

	for i, f := range findings {
		result.Findings[i] = &models.Finding{
			ModuleID:      f.ModuleID,
			Title:         f.Title,
			URL:           f.URL.String,
			Evidence:      f.Evidence.String,
			Severity:      parseSeverity(f.Severity),
			Confidence:    parseConfidence(f.Confidence),
			CWEID:         f.CWEID.String,
			OWASPCategory: f.OWASPCategory.String,
			CVSS: func() *float64 {
				if f.CVSS.Valid {
					v := f.CVSS.Float64
					return &v
				}
				return nil
			}(),
			Parameter:   f.Parameter.String,
			Payload:     f.Payload.String,
			Description: f.Description.String,
			Remediation: f.Remediation.String,
			Request:     f.Request.String,
			Response:    f.Response.String,
		}
	}

	eng := report.New(&report.Config{
		OutputDir:       filepath.Join(os.Getenv("HOME"), ".fang", "reports"),
		Formats:         []string{format},
		IncludeEvidence: true,
	})

	paths, err := eng.Generate(a.ctx, result)
	if err != nil {
		return "", fmt.Errorf("generate report: %w", err)
	}

	if len(paths) > 0 {
		return paths[0], nil
	}
	return "", fmt.Errorf("no report generated")
}

func (a *App) CreateSchedule(input ScheduleInput) (string, error) {
	id, err := db.CreateSchedule(input.TargetID, input.Name, input.CronExpr, input.Modules, input.NotifyOn, input.WebhookURL, "")
	if err != nil {
		return "", err
	}
	a.scheduler.Add(id, input.CronExpr)
	return id, nil
}

func (a *App) GetSchedules() ([]db.ScheduleRow, error) {
	return db.ListSchedules()
}

func (a *App) DeleteSchedule(id string) error {
	a.scheduler.Remove(id)
	return db.DeleteSchedule(id)
}

func (a *App) GetReportDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".fang", "reports")
}

func (a *App) OpenDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}
	return exec.Command("xdg-open", path).Start()
}

func (a *App) GetConfig() *config.AppConfig {
	return config.Get()
}

func (a *App) SaveConfig(cfg *config.AppConfig) error {
	return config.Save(cfg)
}

type AuthResult struct {
	Success  bool   `json:"success"`
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Error    string `json:"error"`
}

func (a *App) Login(username, password string) AuthResult {
	if last, ok := a.loginAttempts[username]; ok && time.Since(last) < time.Second {
		return AuthResult{Success: false, Error: "too many login attempts. wait before trying again."}
	}
	a.loginAttempts[username] = time.Now()

	user, err := db.AuthenticateUser(username, password)
	if err != nil {
		return AuthResult{Success: false, Error: err.Error()}
	}
	a.currentUserID = user.ID
	return AuthResult{
		Success:  true,
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
	}
}

func (a *App) RegisterUser(username, email, password, role string) (string, error) {
	return db.CreateUser(username, email, password, role)
}

func (a *App) ListUsers() ([]db.UserRow, error) {
	return db.ListUsers()
}

func (a *App) DeleteUser(id string) error {
	d := db.DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := d.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

func (a *App) ChangePassword(userID, oldPassword, newPassword string) error {
	d := db.DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}
	var currentHash string
	err := d.QueryRow("SELECT password FROM users WHERE id = ?", userID).Scan(&currentHash)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(oldPassword)); err != nil {
		return fmt.Errorf("invalid current password")
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = d.Exec("UPDATE users SET password = ?, updated_at = ? WHERE id = ?", string(newHash), time.Now(), userID)
	return err
}

type ExportData struct {
	Version    string          `json:"version"`
	ExportedAt string          `json:"exported_at"`
	Findings   []db.FindingRow `json:"findings"`
	Scans      []db.ScanRow    `json:"scans"`
	Targets    []db.TargetRow  `json:"targets"`
}

func (a *App) ExportAll(format string) (string, error) {
	findings, err := db.QueryFindings(db.FindingFilter{Limit: 100000})
	if err != nil {
		return "", fmt.Errorf("export findings: %w", err)
	}
	scans, err := db.QueryScans(db.ScanFilter{Limit: 100000})
	if err != nil {
		return "", fmt.Errorf("export scans: %w", err)
	}
	targets, err := db.ListTargets()
	if err != nil {
		return "", fmt.Errorf("export targets: %w", err)
	}

	data := ExportData{
		Version:    "1.0.0",
		ExportedAt: time.Now().Format(time.RFC3339),
		Findings:   findings,
		Scans:      scans,
		Targets:    targets,
	}

	home, _ := os.UserHomeDir()
	outDir := filepath.Join(home, ".fang", "exports")
	os.MkdirAll(outDir, 0755)
	ts := time.Now().Format("2006-01-02_15-04-05")

	switch format {
	case "json":
		body, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return "", err
		}
		path := filepath.Join(outDir, fmt.Sprintf("fang_export_%s.json", ts))
		if err := os.WriteFile(path, body, 0644); err != nil {
			return "", err
		}
		return path, nil
	case "csv":
		path := filepath.Join(outDir, fmt.Sprintf("fang_export_%s.csv", ts))
		f, err := os.Create(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		f.WriteString("Type,ID,Title,Severity,Module,URL,CreatedAt\n")
		for _, fnd := range findings {
			f.WriteString(fmt.Sprintf("finding,%s,%s,%s,%s,%s,%s\n",
				fnd.ID, escapeCSV(fnd.Title), fnd.Severity, fnd.ModuleID, fnd.URL.String, fnd.CreatedAt.Format(time.RFC3339)))
		}
		return path, nil
	default:
		return "", fmt.Errorf("unsupported export format: %s", format)
	}
}

func (a *App) ImportData(path string) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("invalid path: %w", err)
	}
	if info.IsDir() {
		return 0, fmt.Errorf("path is a directory, not a file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read import file: %w", err)
	}

	var export ExportData
	if err := json.Unmarshal(data, &export); err != nil {
		return 0, fmt.Errorf("parse import: %w", err)
	}

	imported := 0
	tx, err := db.BeginTx()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	for _, t := range export.Targets {
		_, err := tx.Exec(
			`INSERT OR IGNORE INTO targets (id, url, domain, name, tags, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			t.ID, t.URL, t.Domain, t.Name, t.Tags, t.CreatedBy, t.CreatedAt,
		)
		if err == nil {
			imported++
		}
	}
	for _, s := range export.Scans {
		_, err := tx.Exec(
			`INSERT OR IGNORE INTO scans (id, target_id, status, modules, threads, timeout, proxy, triggered_by, schedule_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			s.ID, s.TargetID, s.Status, s.Modules, s.Threads, s.Timeout, s.Proxy, s.TriggeredBy, s.ScheduleID, s.CreatedAt,
		)
		if err == nil {
			imported++
		}
	}
	for _, f := range export.Findings {
		_, err := tx.Exec(
			`INSERT OR IGNORE INTO findings (id, scan_id, target_id, module_id, title, severity, confidence, cwe_id, url, parameter, payload, evidence, description, remediation, request, response, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.ID, f.ScanID, f.TargetID, f.ModuleID, f.Title, f.Severity, f.Confidence, f.CWEID, f.URL, f.Parameter, f.Payload, f.Evidence, f.Description, f.Remediation, f.Request, f.Response, f.CreatedAt,
		)
		if err == nil {
			imported++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit import: %w", err)
	}
	return imported, nil
}

func (a *App) DownloadReport(scanID, format string) (string, error) {
	path, err := a.GenerateReport(scanID, format)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read report: %w", err)
	}

	savePath, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save Report",
		DefaultFilename: filepath.Base(path),
		Filters: []runtime.FileFilter{
			{DisplayName: fmt.Sprintf("%s files", format), Pattern: fmt.Sprintf("*.%s", format)},
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("save dialog: %w", err)
	}
	if savePath == "" {
		return "", fmt.Errorf("cancelled")
	}

	if err := os.WriteFile(savePath, data, 0644); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return savePath, nil
}

func (a *App) GetFinding(id string) (*db.FindingRow, error) {
	return db.GetFinding(id)
}

func (a *App) DeleteScan(id string) error {
	d := db.DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := d.Exec("DELETE FROM scans WHERE id = ?", id)
	return err
}

func (a *App) UpdateFinding(id string, isFalsePositive bool, severity string, notes string) error {
	return db.UpdateFinding(id, isFalsePositive, severity, notes)
}

func escapeCSV(s string) string {
	return fmt.Sprintf("\"%s\"", s)
}

func ensureDefaultUser() {
	users, err := db.ListUsers()
	if err != nil || len(users) > 0 {
		return
	}
	b := make([]byte, 12)
	rand.Read(b)
	defaultPass := hex.EncodeToString(b)
	id, err := db.CreateUser("admin", "admin@fang.local", defaultPass, "admin")
	if err != nil {
		fmt.Printf("[fang] create default user: %v\n", err)
		return
	}
	fmt.Printf("[fang] created default admin user: %s\n", id)
	fmt.Printf("[fang] DEFAULT PASSWORD: %s (CHANGE IMMEDIATELY)\n", defaultPass)
}

func (a *App) CreateJiraIssue(scanID, findingID string) (string, error) {
	cfg := integration.GetConfig()
	if cfg.Jira == nil {
		return "", fmt.Errorf("jira not configured")
	}

	finding, err := db.GetFinding(findingID)
	if err != nil {
		return "", fmt.Errorf("finding not found: %w", err)
	}

	scan, err := db.GetScan(scanID)
	if err != nil {
		return "", fmt.Errorf("scan not found: %w", err)
	}

	target, err := db.GetTarget(scan.TargetID)
	if err != nil {
		return "", fmt.Errorf("target not found: %w", err)
	}

	mf := &models.Finding{
		Title:       finding.Title,
		Severity:    parseSeverity(finding.Severity),
		Confidence:  parseConfidence(finding.Confidence),
		URL:         finding.URL.String,
		Parameter:   finding.Parameter.String,
		Payload:     finding.Payload.String,
		Evidence:    finding.Evidence.String,
		Description: finding.Description.String,
		Remediation: finding.Remediation.String,
		CWEID:       finding.CWEID.String,
		ModuleID:    finding.ModuleID,
	}

	client := integration.NewJiraClient(cfg.Jira)
	ctx := context.Background()
	return client.CreateIssue(ctx, mf, target.URL)
}

func (a *App) CreateGitHubIssue(scanID, findingID string) (string, error) {
	cfg := integration.GetConfig()
	if cfg.GitHub == nil {
		return "", fmt.Errorf("github not configured")
	}

	finding, err := db.GetFinding(findingID)
	if err != nil {
		return "", fmt.Errorf("finding not found: %w", err)
	}

	scan, err := db.GetScan(scanID)
	if err != nil {
		return "", fmt.Errorf("scan not found: %w", err)
	}

	target, err := db.GetTarget(scan.TargetID)
	if err != nil {
		return "", fmt.Errorf("target not found: %w", err)
	}

	mf := &models.Finding{
		Title:       finding.Title,
		Severity:    parseSeverity(finding.Severity),
		Confidence:  parseConfidence(finding.Confidence),
		URL:         finding.URL.String,
		Parameter:   finding.Parameter.String,
		Payload:     finding.Payload.String,
		Evidence:    finding.Evidence.String,
		Description: finding.Description.String,
		Remediation: finding.Remediation.String,
		CWEID:       finding.CWEID.String,
		ModuleID:    finding.ModuleID,
	}

	client := integration.NewGitHubClient(cfg.GitHub)
	ctx := context.Background()
	return client.CreateIssue(ctx, mf, target.URL)
}

func (a *App) ConfigureIntegration(integType, configJSON string) error {
	cfg := integration.GetConfig()

	switch integType {
	case "jira":
		var jc integration.JiraConfig
		if err := json.Unmarshal([]byte(configJSON), &jc); err != nil {
			return fmt.Errorf("invalid jira config: %w", err)
		}
		cfg.Jira = &jc
	case "github":
		var gc integration.GitHubConfig
		if err := json.Unmarshal([]byte(configJSON), &gc); err != nil {
			return fmt.Errorf("invalid github config: %w", err)
		}
		cfg.GitHub = &gc
	case "slack":
		var sc integration.SlackConfig
		if err := json.Unmarshal([]byte(configJSON), &sc); err != nil {
			return fmt.Errorf("invalid slack config: %w", err)
		}
		cfg.Slack = &sc
	default:
		return fmt.Errorf("unknown integration type: %s", integType)
	}

	return integration.SaveConfig(cfg)
}

func (a *App) GetIntegrationConfig(integType string) (string, error) {
	cfg := integration.GetConfig()

	var val interface{}
	switch integType {
	case "jira":
		val = cfg.Jira
	case "github":
		val = cfg.GitHub
	case "slack":
		val = cfg.Slack
	default:
		return "", fmt.Errorf("unknown integration type: %s", integType)
	}

	if val == nil {
		return "{}", nil
	}

	data, err := json.Marshal(val)
	if err != nil {
		return "", fmt.Errorf("marshal config: %w", err)
	}
	return string(data), nil
}

func (a *App) CreateWorkflow(name string, triggerType string, conditions string, actions string) (string, error) {
	id := uuid.New().String()

	var condMap map[string]string
	if err := json.Unmarshal([]byte(conditions), &condMap); err != nil {
		condMap = make(map[string]string)
	}
	if condMap == nil {
		condMap = make(map[string]string)
	}

	var actionCfgs []workflow.ActionConfig
	if err := json.Unmarshal([]byte(actions), &actionCfgs); err != nil {
		return "", fmt.Errorf("invalid actions json: %w", err)
	}

	w := &workflow.Workflow{
		ID:      id,
		Name:    name,
		Enabled: true,
		Trigger: workflow.TriggerConfig{
			Type:       workflow.TriggerType(triggerType),
			Conditions: condMap,
		},
		Actions:   actionCfgs,
		CreatedAt: time.Now(),
	}

	if err := a.workflowEng.Add(w); err != nil {
		return "", err
	}

	a.saveWorkflows()
	return id, nil
}

func (a *App) ListWorkflows() ([]*workflow.Workflow, error) {
	return a.workflowEng.List(), nil
}

func (a *App) DeleteWorkflow(id string) error {
	a.workflowEng.Remove(id)
	a.saveWorkflows()
	return nil
}

func (a *App) ToggleWorkflow(id string, enabled bool) error {
	for _, w := range a.workflowEng.List() {
		if w.ID == id {
			w.Enabled = enabled
			a.saveWorkflows()
			return nil
		}
	}
	return fmt.Errorf("workflow not found: %s", id)
}

func (a *App) TestWorkflow(id string) (string, error) {
	for _, w := range a.workflowEng.List() {
		if w.ID == id {
			if !w.Enabled {
				return "", fmt.Errorf("workflow is disabled")
			}
			go a.workflowEng.Execute(context.Background(), w.Trigger.Type, map[string]interface{}{
				"test":         true,
				"workflow":     w.Name,
				"triggered_at": time.Now().Format(time.RFC3339),
			})
			return "workflow test executed", nil
		}
	}
	return "", fmt.Errorf("workflow not found: %s", id)
}

func (a *App) saveWorkflows() {
	path := filepath.Join(os.Getenv("HOME"), ".fang", "config", "workflows.json")
	if err := workflow.SaveWorkflows(a.workflowEng.List(), path); err != nil {
		fmt.Printf("[fang] save workflows: %v\n", err)
	}
}

func (a *App) CreateOrg(name, domain string) (string, error) {
	return db.CreateOrganization(name, domain, a.currentUserID)
}

func (a *App) ListOrgs() ([]db.OrganizationRow, error) {
	return db.ListOrganizations()
}

func (a *App) DeleteOrg(id string) error {
	return db.DeleteOrganization(id)
}

func (a *App) InviteUser(orgID, username, role string) error {
	d := db.DB()
	if d == nil {
		return fmt.Errorf("database not initialized")
	}
	var userID string
	err := d.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	if err := db.AddOrgMember(orgID, userID, role); err != nil {
		return err
	}
	db.LogAuditEvent(a.currentUserID, orgID, "invite_user", "user:"+username, fmt.Sprintf("added as %s", role))
	return nil
}

func (a *App) RemoveUser(orgID, userID string) error {
	if err := db.RemoveOrgMember(orgID, userID); err != nil {
		return err
	}
	db.LogAuditEvent(a.currentUserID, orgID, "remove_user", "user:"+userID, "removed from organization")
	return nil
}

func (a *App) ListOrgMembers(orgID string) ([]db.OrgMemberRow, error) {
	return db.ListOrgMembers(orgID)
}

func (a *App) GetAuditLog(orgID string) ([]db.AuditEntry, error) {
	return db.QueryAuditLog(orgID, 100)
}

func (a *App) GetPluginDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".fang", "plugins")
}

func (a *App) ListPlugins() string {
	plugins := a.pluginMgr.List()
	type pluginInfo struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Version     string `json:"version"`
		Author      string `json:"author"`
		Description string `json:"description"`
		Type        string `json:"type"`
	}
	info := make([]pluginInfo, 0, len(plugins))
	for _, p := range plugins {
		info = append(info, pluginInfo{
			ID:          p.Manifest.ID,
			Name:        p.Manifest.Name,
			Version:     p.Manifest.Version,
			Author:      p.Manifest.Author,
			Description: p.Manifest.Description,
			Type:        string(p.Manifest.Type),
		})
	}
	data, _ := json.Marshal(info)
	return string(data)
}

func (a *App) GetEvasionConfig() string {
	cfg := a.evasionEng.Config()
	data, _ := json.Marshal(cfg)
	return string(data)
}

func (a *App) SaveEvasionConfig(configJSON string) error {
	var cfg evasion.EvasionConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("invalid evasion config: %w", err)
	}
	a.evasionEng.UpdateConfig(&cfg)
	return nil
}

func (a *App) ConfigureSIEM(configJSON string) error {
	var cfg integration.SIEMConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("invalid siem config: %w", err)
	}

	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".fang", "config", "siem.json")
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("siem config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal siem config: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write siem config: %w", err)
	}

	a.siemCfg = &cfg
	return nil
}

func (a *App) GetSIEMConfig() string {
	if a.siemCfg == nil {
		return "{}"
	}
	data, _ := json.Marshal(a.siemCfg)
	return string(data)
}

func (a *App) SendToSIEM(scanID string) error {
	if a.siemCfg == nil {
		return fmt.Errorf("siem not configured")
	}

	scan, err := db.GetScan(scanID)
	if err != nil {
		return fmt.Errorf("scan not found: %w", err)
	}
	target, err := db.GetTarget(scan.TargetID)
	if err != nil {
		return fmt.Errorf("target not found: %w", err)
	}

	findings, err := db.QueryFindings(db.FindingFilter{ScanID: scanID, Limit: 10000})
	if err != nil {
		return fmt.Errorf("query findings: %w", err)
	}

	client := integration.NewSIEMClient(a.siemCfg)

	for _, f := range findings {
		mf := &models.Finding{
			Title:       f.Title,
			Severity:    parseSeverity(f.Severity),
			Confidence:  parseConfidence(f.Confidence),
			URL:         f.URL.String,
			Parameter:   f.Parameter.String,
			Payload:     f.Payload.String,
			Evidence:    f.Evidence.String,
			Description: f.Description.String,
			Remediation: f.Remediation.String,
			CWEID:       f.CWEID.String,
			ModuleID:    f.ModuleID,
		}
		if err := client.SendFinding(a.ctx, mf, target.URL); err != nil {
			fmt.Printf("[fang] siem send finding: %v\n", err)
		}
	}

	return nil
}

func (a *App) SetLanguage(lang string) error {
	l := i18n.Lang(lang)
	i18n.Default.SetLang(l)
	a.lang = lang
	return nil
}

func (a *App) GetLanguage() string {
	return a.lang
}

func (a *App) GetTranslation(key string) string {
	return i18n.Default.T(key)
}

func (a *App) CreateBountyReport(findingID, platform string) (string, error) {
	finding, err := db.GetFinding(findingID)
	if err != nil {
		return "", fmt.Errorf("finding not found: %w", err)
	}

	cfg := &bugbounty.BugBountyConfig{
		Platform: bugbounty.Platform(platform),
	}

	client := bugbounty.New(cfg)

	mf := &models.Finding{
		Title:       finding.Title,
		Severity:    parseSeverity(finding.Severity),
		Confidence:  parseConfidence(finding.Confidence),
		URL:         finding.URL.String,
		Parameter:   finding.Parameter.String,
		Payload:     finding.Payload.String,
		Evidence:    finding.Evidence.String,
		Description: finding.Description.String,
		Remediation: finding.Remediation.String,
		CWEID:       finding.CWEID.String,
		ModuleID:    finding.ModuleID,
	}

	ctx := context.Background()
	draftID, err := client.CreateDraftReport(ctx, mf)
	if err != nil {
		return "", fmt.Errorf("create draft: %w", err)
	}

	return draftID, nil
}

func parseSeverity(s string) models.Severity {
	switch s {
	case "CRITICAL":
		return models.Critical
	case "HIGH":
		return models.High
	case "MEDIUM":
		return models.Medium
	case "LOW":
		return models.Low
	default:
		return models.Info
	}
}

func parseConfidence(s string) models.Confidence {
	switch s {
	case "CRITICAL":
		return models.CriticalConfidence
	case "HIGH":
		return models.HighConfidence
	case "MEDIUM":
		return models.MediumConfidence
	case "LOW":
		return models.LowConfidence
	default:
		return models.Tentative
	}
}
