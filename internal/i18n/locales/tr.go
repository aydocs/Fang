package locales

import "github.com/aydocs/fang/internal/i18n"

func init() {
	i18n.Default.Register(i18n.TR, map[string]string{
		"scan_running":   "Tarama çalışıyor",
		"scan_completed": "Tarama tamamlandı",
		"scan_failed":    "Tarama başarısız",
		"target":         "Hedef",
		"findings":       "Bulgular",
		"severity":       "Şiddet",
		"critical":       "Kritik",
		"high":           "Yüksek",
		"medium":         "Orta",
		"low":            "Düşük",
		"info":           "Bilgi",
		"dashboard":      "Kontrol Paneli",
		"scanner":        "Tarayıcı",
		"targets":        "Hedefler",
		"reports":        "Raporlar",
		"settings":       "Ayarlar",
		"users":          "Kullanıcılar",
		"notifications":  "Bildirimler",
		"organizations":  "Organizasyonlar",
		"integrations":   "Entegrasyonlar",
		"workflows":      "İş Akışları",
		"evasion":        "Kaçınma",
		"login":          "Giriş",
		"register":       "Kayıt",
		"username":       "Kullanıcı Adı",
		"password":       "Şifre",
		"email":          "E-posta",
		"save":           "Kaydet",
		"cancel":         "İptal",
		"delete":         "Sil",
		"create":         "Oluştur",
		"edit":           "Düzenle",
		"search":         "Ara",
		"export":         "Dışa Aktar",
		"import":         "İçe Aktar",
		"language":       "Dil",
	})
}
