package locales

import "github.com/aydocs/fang/internal/i18n"

func init() {
	i18n.Default.Register(i18n.ZH, map[string]string{
		"scan_running":   "扫描进行中",
		"scan_completed": "扫描完成",
		"scan_failed":    "扫描失败",
		"target":         "目标",
		"findings":       "发现",
		"severity":       "严重性",
		"critical":       "严重",
		"high":           "高",
		"medium":         "中",
		"low":            "低",
		"info":           "信息",
		"dashboard":      "仪表盘",
		"scanner":        "扫描器",
		"targets":        "目标",
		"reports":        "报告",
		"settings":       "设置",
		"users":          "用户",
		"notifications":  "通知",
		"organizations":  "组织",
		"integrations":   "集成",
		"workflows":      "工作流",
		"evasion":        "规避",
		"login":          "登录",
		"register":       "注册",
		"username":       "用户名",
		"password":       "密码",
		"email":          "邮箱",
		"save":           "保存",
		"cancel":         "取消",
		"delete":         "删除",
		"create":         "创建",
		"edit":           "编辑",
		"search":         "搜索",
		"export":         "导出",
		"import":         "导入",
		"language":       "语言",
	})
}
