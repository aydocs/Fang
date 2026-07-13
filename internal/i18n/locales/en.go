package locales

import "github.com/aydocs/fang/internal/i18n"

func init() {
	i18n.Default.Register(i18n.EN, map[string]string{
		"scan_running":   "Scan is running",
		"scan_completed": "Scan completed",
		"scan_failed":    "Scan failed",
		"target":         "Target",
		"findings":       "Findings",
		"severity":       "Severity",
		"critical":       "Critical",
		"high":           "High",
		"medium":         "Medium",
		"low":            "Low",
		"info":           "Info",
		"dashboard":      "Dashboard",
		"scanner":        "Scanner",
		"targets":        "Targets",
		"reports":        "Reports",
		"settings":       "Settings",
		"users":          "Users",
		"notifications":  "Notifications",
		"organizations":  "Organizations",
		"integrations":   "Integrations",
		"workflows":      "Workflows",
		"evasion":        "Evasion",
		"login":          "Login",
		"register":       "Register",
		"username":       "Username",
		"password":       "Password",
		"email":          "Email",
		"save":           "Save",
		"cancel":         "Cancel",
		"delete":         "Delete",
		"create":         "Create",
		"edit":           "Edit",
		"search":         "Search",
		"export":         "Export",
		"import":         "Import",
		"language":       "Language",
	})
}
