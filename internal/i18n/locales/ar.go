package locales

import "github.com/aydocs/fang/internal/i18n"

func init() {
	i18n.Default.Register(i18n.AR, map[string]string{
		"scan_running":   "جارٍ الفحص",
		"scan_completed": "اكتمل الفحص",
		"scan_failed":    "فشل الفحص",
		"target":         "الهدف",
		"findings":       "النتائج",
		"severity":       "الخطورة",
		"critical":       "حرج",
		"high":           "عالٍ",
		"medium":         "متوسط",
		"low":            "منخفض",
		"info":           "معلومات",
		"dashboard":      "لوحة التحكم",
		"scanner":        "الماسح",
		"targets":        "الأهداف",
		"reports":        "التقارير",
		"settings":       "الإعدادات",
		"users":          "المستخدمون",
		"notifications":  "الإشعارات",
		"organizations":  "المنظمات",
		"integrations":   "التكاملات",
		"workflows":      "سير العمل",
		"evasion":        "التحايل",
		"login":          "تسجيل الدخول",
		"register":       "تسجيل",
		"username":       "اسم المستخدم",
		"password":       "كلمة المرور",
		"email":          "البريد الإلكتروني",
		"save":           "حفظ",
		"cancel":         "إلغاء",
		"delete":         "حذف",
		"create":         "إنشاء",
		"edit":           "تحرير",
		"search":         "بحث",
		"export":         "تصدير",
		"import":         "استيراد",
		"language":       "اللغة",
	})
}
