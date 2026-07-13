package locales

import "github.com/aydocs/fang/internal/i18n"

func init() {
	i18n.Default.Register(i18n.FR, map[string]string{
		"scan_running":   "Analyse en cours",
		"scan_completed": "Analyse terminée",
		"scan_failed":    "Analyse échouée",
		"target":         "Cible",
		"findings":       "Résultats",
		"severity":       "Sévérité",
		"critical":       "Critique",
		"high":           "Élevé",
		"medium":         "Moyen",
		"low":            "Faible",
		"info":           "Info",
		"dashboard":      "Tableau de bord",
		"scanner":        "Analyseur",
		"targets":        "Cibles",
		"reports":        "Rapports",
		"settings":       "Paramètres",
		"users":          "Utilisateurs",
		"notifications":  "Notifications",
		"organizations":  "Organisations",
		"integrations":   "Intégrations",
		"workflows":      "Flux de travail",
		"evasion":        "Contournement",
		"login":          "Connexion",
		"register":       "S'inscrire",
		"username":       "Nom d'utilisateur",
		"password":       "Mot de passe",
		"email":          "E-mail",
		"save":           "Enregistrer",
		"cancel":         "Annuler",
		"delete":         "Supprimer",
		"create":         "Créer",
		"edit":           "Modifier",
		"search":         "Rechercher",
		"export":         "Exporter",
		"import":         "Importer",
		"language":       "Langue",
	})
}
