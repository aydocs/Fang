package locales

import "github.com/aydocs/fang/internal/i18n"

func init() {
	i18n.Default.Register(i18n.DE, map[string]string{
		"scan_running":   "Scan läuft",
		"scan_completed": "Scan abgeschlossen",
		"scan_failed":    "Scan fehlgeschlagen",
		"target":         "Ziel",
		"findings":       "Ergebnisse",
		"severity":       "Schweregrad",
		"critical":       "Kritisch",
		"high":           "Hoch",
		"medium":         "Mittel",
		"low":            "Niedrig",
		"info":           "Info",
		"dashboard":      "Dashboard",
		"scanner":        "Scanner",
		"targets":        "Ziele",
		"reports":        "Berichte",
		"settings":       "Einstellungen",
		"users":          "Benutzer",
		"notifications":  "Benachrichtigungen",
		"organizations":  "Organisationen",
		"integrations":   "Integrationen",
		"workflows":      "Workflows",
		"evasion":        "Umgehung",
		"login":          "Anmelden",
		"register":       "Registrieren",
		"username":       "Benutzername",
		"password":       "Passwort",
		"email":          "E-Mail",
		"save":           "Speichern",
		"cancel":         "Abbrechen",
		"delete":         "Löschen",
		"create":         "Erstellen",
		"edit":           "Bearbeiten",
		"search":         "Suchen",
		"export":         "Exportieren",
		"import":         "Importieren",
		"language":       "Sprache",
	})
}
