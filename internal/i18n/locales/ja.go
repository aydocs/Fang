package locales

import "github.com/aydocs/fang/internal/i18n"

func init() {
	i18n.Default.Register(i18n.JA, map[string]string{
		"scan_running":   "スキャン実行中",
		"scan_completed": "スキャン完了",
		"scan_failed":    "スキャン失敗",
		"target":         "ターゲット",
		"findings":       "発見事項",
		"severity":       "重要度",
		"critical":       "致命的",
		"high":           "高",
		"medium":         "中",
		"low":            "低",
		"info":           "情報",
		"dashboard":      "ダッシュボード",
		"scanner":        "スキャナー",
		"targets":        "ターゲット一覧",
		"reports":        "レポート",
		"settings":       "設定",
		"users":          "ユーザー",
		"notifications":  "通知",
		"organizations":  "組織",
		"integrations":   "連携",
		"workflows":      "ワークフロー",
		"evasion":        "回避",
		"login":          "ログイン",
		"register":       "登録",
		"username":       "ユーザー名",
		"password":       "パスワード",
		"email":          "メール",
		"save":           "保存",
		"cancel":         "キャンセル",
		"delete":         "削除",
		"create":         "作成",
		"edit":           "編集",
		"search":         "検索",
		"export":         "エクスポート",
		"import":         "インポート",
		"language":       "言語",
	})
}
