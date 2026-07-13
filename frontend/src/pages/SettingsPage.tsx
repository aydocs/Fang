import { useEffect, useState } from 'react'
import { bridge } from '../bridge'
import { FolderOpen, RefreshCw, Save, Settings as SettingsIcon, Globe, Download, Upload } from 'lucide-react'
import { BrowserOpenURL } from '../../wailsjs/runtime/runtime'
import type { ModuleInfo } from '../types'

const languages: { code: string; name: string }[] = [
  { code: 'en', name: 'English' },
  { code: 'tr', name: 'Türkçe' },
  { code: 'de', name: 'Deutsch' },
  { code: 'fr', name: 'Français' },
  { code: 'es', name: 'Español' },
  { code: 'ru', name: 'Русский' },
  { code: 'zh', name: '中文' },
  { code: 'ar', name: 'العربية' },
  { code: 'ja', name: '日本語' },
]

interface AppConfig {
  theme: string
  default_threads: number
  default_timeout: number
  save_reports: boolean
  report_format: string
  notifications_enabled: boolean
  notify_on_scan: boolean
  notify_on_error: boolean
  auto_refresh: boolean
  refresh_interval: number
}

export default function SettingsPage() {
  const [reportDir, setReportDir] = useState('')
  const [modules, setModules] = useState<ModuleInfo[]>([])
  const [expanded, setExpanded] = useState(false)
  const [config, setConfig] = useState<AppConfig | null>(null)
  const [saved, setSaved] = useState(false)
  const [importPath, setImportPath] = useState('')
  const [currentLang, setCurrentLang] = useState('en')

  useEffect(() => {
    bridge().GetReportDir().then(setReportDir).catch(console.error)
    bridge().ListModules().then(setModules).catch(console.error)
    bridge().GetConfig().then((c) => setConfig(c as unknown as AppConfig)).catch(console.error)
    bridge().GetLanguage().then(setCurrentLang).catch(() => {})
  }, [])

  const changeLanguage = async (code: string) => {
    try {
      await bridge().SetLanguage(code)
      setCurrentLang(code)
    } catch (e: any) {
      console.error('Failed to set language:', e)
    }
  }

  const saveConfig = async () => {
    if (!config) return
    try {
      await bridge().SaveConfig(config as unknown as Record<string, unknown>)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (e: any) {
      alert('Failed to save config: ' + e)
    }
  }

  const doImport = async () => {
    if (!importPath) return
    try {
      const count = await bridge().ImportData(importPath)
      alert(`Imported ${count} records.`)
      setImportPath('')
    } catch (e: any) {
      alert('Import failed: ' + e)
    }
  }

  if (!config) return <div className="text-gray-500">Loading...</div>

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>

      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Globe className="w-4 h-4" />
            Language
          </h2>
          <select
            className="input w-48"
            value={currentLang}
            onChange={(e) => changeLanguage(e.target.value)}
          >
            {languages.map((l) => (
              <option key={l.code} value={l.code}>{l.name}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <SettingsIcon className="w-4 h-4" />
            Application Config
          </h2>
          <button
            onClick={saveConfig}
            className={`btn-primary text-xs flex items-center gap-1 ${saved ? 'bg-green-600' : ''}`}
          >
            <Save className="w-3.5 h-3.5" />
            {saved ? 'Saved!' : 'Save'}
          </button>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-sm text-gray-400 mb-1 block">Default Threads</label>
            <input
              type="number"
              className="input"
              value={config.default_threads}
              onChange={(e) => setConfig({ ...config, default_threads: parseInt(e.target.value) || 20 })}
            />
          </div>
          <div>
            <label className="text-sm text-gray-400 mb-1 block">Default Timeout (s)</label>
            <input
              type="number"
              className="input"
              value={config.default_timeout}
              onChange={(e) => setConfig({ ...config, default_timeout: parseInt(e.target.value) || 10 })}
            />
          </div>
          <div>
            <label className="text-sm text-gray-400 mb-1 block">Report Format</label>
            <select
              className="input"
              value={config.report_format}
              onChange={(e) => setConfig({ ...config, report_format: e.target.value })}
            >
              <option value="html">HTML</option>
              <option value="json">JSON</option>
              <option value="md">Markdown</option>
              <option value="sarif">SARIF</option>
            </select>
          </div>
          <div>
            <label className="text-sm text-gray-400 mb-1 block">Refresh Interval (s)</label>
            <input
              type="number"
              className="input"
              value={config.refresh_interval}
              onChange={(e) => setConfig({ ...config, refresh_interval: parseInt(e.target.value) || 10 })}
            />
          </div>
        </div>

        <div className="flex flex-wrap gap-4">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={config.save_reports}
              onChange={(e) => setConfig({ ...config, save_reports: e.target.checked })}
              className="rounded bg-fang-900 border-fang-600"
            />
            Save reports
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={config.notifications_enabled}
              onChange={(e) => setConfig({ ...config, notifications_enabled: e.target.checked })}
              className="rounded bg-fang-900 border-fang-600"
            />
            Notifications
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={config.auto_refresh}
              onChange={(e) => setConfig({ ...config, auto_refresh: e.target.checked })}
              className="rounded bg-fang-900 border-fang-600"
            />
            Auto refresh
          </label>
        </div>
      </div>

      <div className="card space-y-4">
        <h2 className="text-lg font-semibold">Application</h2>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Version</p>
              <p className="text-xs text-gray-500">Fang Security Scanner</p>
            </div>
            <span className="text-sm text-fang-300">v1.0.0</span>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Report Directory</p>
              <p className="text-xs text-gray-500 font-mono">{reportDir}</p>
            </div>
            <button
              onClick={() => { if (reportDir) BrowserOpenURL(reportDir) }}
              className="btn-ghost text-xs flex items-center gap-1"
            >
              <FolderOpen className="w-3.5 h-3.5" />
              Open
            </button>
          </div>
        </div>
      </div>

      <div className="card space-y-4">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Download className="w-4 h-4" />
          Export / Import
        </h2>
        <div className="flex items-center gap-3">
          <button
            onClick={async () => {
              try {
                const path = await bridge().ExportAll('json')
                alert(`Exported to: ${path}`)
              } catch (e: any) {
                alert('Export failed: ' + e)
              }
            }}
            className="btn-primary text-xs flex items-center gap-1"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON
          </button>
          <button
            onClick={async () => {
              try {
                const path = await bridge().ExportAll('csv')
                alert(`Exported to: ${path}`)
              } catch (e: any) {
                alert('Export failed: ' + e)
              }
            }}
            className="btn-ghost text-xs flex items-center gap-1"
          >
            <Download className="w-3.5 h-3.5" />
            Export CSV
          </button>
        </div>
        <div className="flex items-center gap-3">
          <input
            className="input flex-1"
            placeholder="/path/to/fang_export.json"
            value={importPath}
            onChange={(e) => setImportPath(e.target.value)}
          />
          <button
            onClick={doImport}
            disabled={!importPath}
            className="btn-ghost text-xs flex items-center gap-1"
          >
            <Upload className="w-3.5 h-3.5" />
            Import
          </button>
        </div>
      </div>

      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">
            Modules ({modules.length})
          </h2>
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-xs text-fang-300 hover:text-fang-200 flex items-center gap-1"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            {expanded ? 'Collapse' : 'Expand'}
          </button>
        </div>

        {expanded ? (
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {modules.map((m) => (
              <div
                key={m.id}
                className="flex items-center justify-between bg-fang-700 rounded-lg p-3"
              >
                <div>
                  <p className="text-sm font-medium">{m.name || m.id}</p>
                  <p className="text-xs text-gray-500">{m.description}</p>
                </div>
                <span className={`badge-${m.severity.toLowerCase()}`}>{m.severity}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-4 gap-2">
            {modules.slice(0, 12).map((m) => (
              <div key={m.id} className="bg-fang-700 rounded-lg p-2 text-center">
                <p className="text-xs font-medium truncate">{m.id}</p>
                <p className="text-[10px] text-gray-500">{m.severity}</p>
              </div>
            ))}
            {modules.length > 12 && (
              <div className="bg-fang-700 rounded-lg p-2 text-center flex items-center justify-center">
                <p className="text-xs text-gray-400">+{modules.length - 12} more</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
