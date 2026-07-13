package locales

import "github.com/aydocs/fang/internal/i18n"

func init() {
	i18n.Default.Register(i18n.ES, map[string]string{
		"scan_running":   "Escaneo en ejecución",
		"scan_completed": "Escaneo completado",
		"scan_failed":    "Escaneo fallido",
		"target":         "Objetivo",
		"findings":       "Hallazgos",
		"severity":       "Gravedad",
		"critical":       "Crítico",
		"high":           "Alto",
		"medium":         "Medio",
		"low":            "Bajo",
		"info":           "Información",
		"dashboard":      "Panel",
		"scanner":        "Escáner",
		"targets":        "Objetivos",
		"reports":        "Informes",
		"settings":       "Ajustes",
		"users":          "Usuarios",
		"notifications":  "Notificaciones",
		"organizations":  "Organizaciones",
		"integrations":   "Integraciones",
		"workflows":      "Flujos de trabajo",
		"evasion":        "Evasión",
		"login":          "Iniciar sesión",
		"register":       "Registrarse",
		"username":       "Nombre de usuario",
		"password":       "Contraseña",
		"email":          "Correo electrónico",
		"save":           "Guardar",
		"cancel":         "Cancelar",
		"delete":         "Eliminar",
		"create":         "Crear",
		"edit":           "Editar",
		"search":         "Buscar",
		"export":         "Exportar",
		"import":         "Importar",
		"language":       "Idioma",
	})
}
