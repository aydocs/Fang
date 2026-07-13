package locales

import "github.com/aydocs/fang/internal/i18n"

func init() {
	i18n.Default.Register(i18n.RU, map[string]string{
		"scan_running":   "Сканирование выполняется",
		"scan_completed": "Сканирование завершено",
		"scan_failed":    "Сканирование не удалось",
		"target":         "Цель",
		"findings":       "Результаты",
		"severity":       "Серьёзность",
		"critical":       "Критический",
		"high":           "Высокий",
		"medium":         "Средний",
		"low":            "Низкий",
		"info":           "Информация",
		"dashboard":      "Панель управления",
		"scanner":        "Сканер",
		"targets":        "Цели",
		"reports":        "Отчёты",
		"settings":       "Настройки",
		"users":          "Пользователи",
		"notifications":  "Уведомления",
		"organizations":  "Организации",
		"integrations":   "Интеграции",
		"workflows":      "Рабочие процессы",
		"evasion":        "Обход",
		"login":          "Вход",
		"register":       "Регистрация",
		"username":       "Имя пользователя",
		"password":       "Пароль",
		"email":          "Эл. почта",
		"save":           "Сохранить",
		"cancel":         "Отмена",
		"delete":         "Удалить",
		"create":         "Создать",
		"edit":           "Редактировать",
		"search":         "Поиск",
		"export":         "Экспорт",
		"import":         "Импорт",
		"language":       "Язык",
	})
}
