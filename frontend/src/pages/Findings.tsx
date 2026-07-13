import { useEffect, useState } from 'react'
import { bridge } from '../bridge'
import { Search, X, ExternalLink, FileDown, FileUp, Download, Filter } from 'lucide-react'
import type { SeverityStat, ModuleStat, FindingRow } from '../types'

export default function Findings() {
  const [severity, setSeverity] = useState<SeverityStat[]>([])
  const [modules, setModules] = useState<ModuleStat[]>([])
  const [findings, setFindings] = useState<FindingRow[]>([])
  const [search, setSearch] = useState('')
  const [detailModal, setDetailModal] = useState<FindingRow | null>(null)
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterModule, setFilterModule] = useState('')

  useEffect(() => {
    bridge().GetSeverityStats().then(setSeverity)
    bridge().GetModuleStats().then(setModules)
    bridge().GetAllFindings(200, 0).then(setFindings)
  }, [])

  const filtered = findings.filter((f) => {
    const fUrl = f.URL?.String || ''
    if (search && !f.Title?.toLowerCase().includes(search.toLowerCase()) &&
        !f.ModuleID?.toLowerCase().includes(search.toLowerCase()) &&
        !fUrl.toLowerCase().includes(search.toLowerCase())) {
      return false
    }
    if (filterSeverity && f.Severity !== filterSeverity) return false
    if (filterModule && f.ModuleID !== filterModule) return false
    return true
  })

  const moduleOptions = [...new Set(findings.map((f) => f.ModuleID).filter(Boolean))]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Findings</h1>
        <div className="flex items-center gap-2">
          <button
            onClick={async () => {
              try {
                const path = await bridge().ExportAll('json')
                alert(`Exported to: ${path}`)
              } catch (e: any) {
                alert('Export failed: ' + e)
              }
            }}
            className="btn-ghost text-xs flex items-center gap-1"
          >
            <FileUp className="w-3.5 h-3.5" />
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
            <FileDown className="w-3.5 h-3.5" />
            Export CSV
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">By Severity</h2>
          <div className="space-y-3">
            {severity.map((s) => (
              <div key={s.severity} className="flex items-center justify-between">
                <span className={`badge-${s.severity?.toLowerCase() || 'info'}`}>{s.severity}</span>
                <span className="font-bold text-lg">{s.count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-4">By Module</h2>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {modules.map((m) => (
              <div key={m.module_id} className="flex items-center justify-between text-sm">
                <span className="font-mono">{m.module_id}</span>
                <span className="text-gray-400">{m.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">All Findings ({filtered.length})</h2>
          <div className="flex items-center gap-3">
            <select
              className="input w-auto text-xs"
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>
            <select
              className="input w-auto text-xs"
              value={filterModule}
              onChange={(e) => setFilterModule(e.target.value)}
            >
              <option value="">All Modules</option>
              {moduleOptions.map((m) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
              <input
                className="input pl-9 w-64"
                placeholder="Search findings..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>
        </div>
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {filtered.slice(0, 50).map((f) => (
            <div
              key={f.ID}
              className="bg-fang-700 rounded-lg p-3 border border-fang-600 text-sm cursor-pointer hover:border-fang-400 transition-colors"
              onClick={() => setDetailModal(f)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="font-medium">{f.Title}</span>
                  <span className="text-xs text-gray-500 font-mono">{f.ModuleID}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`badge-${f.Severity?.toLowerCase() || 'info'}`}>{f.Severity}</span>
                  <ExternalLink className="w-3.5 h-3.5 text-gray-500" />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {detailModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setDetailModal(null)}>
          <div
            className="bg-fang-800 rounded-xl border border-fang-600 w-full max-w-3xl max-h-[85vh] overflow-y-auto m-4"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="sticky top-0 bg-fang-800 border-b border-fang-600 px-6 py-4 flex items-center justify-between z-10">
              <div className="flex items-center gap-3">
                <h2 className="text-lg font-bold">{detailModal.Title}</h2>
                <span className={`badge-${detailModal.Severity?.toLowerCase() || 'info'}`}>
                  {detailModal.Severity}
                </span>
              </div>
              <button
                onClick={() => setDetailModal(null)}
                className="w-8 h-8 flex items-center justify-center rounded hover:bg-fang-700 text-gray-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4 text-sm">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-gray-500">Module</span>
                  <p className="font-mono">{detailModal.ModuleID}</p>
                </div>
                <div>
                  <span className="text-gray-500">Confidence</span>
                  <p>{detailModal.Confidence}</p>
                </div>
                {detailModal.CWEID?.String && (
                  <div>
                    <span className="text-gray-500">CWE</span>
                    <p>{detailModal.CWEID.String}</p>
                  </div>
                )}
                {detailModal.OWASPCategory?.String && (
                  <div>
                    <span className="text-gray-500">OWASP</span>
                    <p>{detailModal.OWASPCategory.String}</p>
                  </div>
                )}
                {detailModal.CVSS != null && detailModal.CVSS.Float64 > 0 && (
                  <div>
                    <span className="text-gray-500">CVSS</span>
                    <p>{detailModal.CVSS.Float64}</p>
                  </div>
                )}
              </div>

              {detailModal.URL?.String && (
                <div>
                  <span className="text-gray-500">URL</span>
                  <p className="font-mono text-fang-300 break-all">{detailModal.URL.String}</p>
                </div>
              )}

              {detailModal.Parameter?.String && (
                <div>
                  <span className="text-gray-500">Parameter</span>
                  <p className="font-mono">{detailModal.Parameter.String}</p>
                </div>
              )}

              {detailModal.Payload?.String && (
                <div>
                  <span className="text-gray-500">Payload</span>
                  <pre className="bg-fang-900 p-3 rounded overflow-x-auto mt-1 text-xs">{detailModal.Payload.String}</pre>
                </div>
              )}

              {detailModal.Description?.String && (
                <div>
                  <span className="text-gray-500">Description</span>
                  <p className="mt-1">{detailModal.Description.String}</p>
                </div>
              )}

              {detailModal.Remediation?.String && (
                <div>
                  <span className="text-gray-500">Remediation</span>
                  <p className="mt-1 text-green-300">{detailModal.Remediation.String}</p>
                </div>
              )}

              {detailModal.Evidence?.String && (
                <div>
                  <span className="text-gray-500">Evidence</span>
                  <pre className="bg-fang-900 p-3 rounded overflow-x-auto mt-1 text-xs max-h-48 overflow-y-auto">
                    {detailModal.Evidence.String}
                  </pre>
                </div>
              )}

              {detailModal.Request?.String && (
                <div>
                  <span className="text-gray-500">Request</span>
                  <pre className="bg-fang-900 p-3 rounded overflow-x-auto mt-1 text-xs max-h-48 overflow-y-auto">
                    {detailModal.Request.String}
                  </pre>
                </div>
              )}

              {detailModal.Response?.String && (
                <div>
                  <span className="text-gray-500">Response</span>
                  <pre className="bg-fang-900 p-3 rounded overflow-x-auto mt-1 text-xs max-h-48 overflow-y-auto">
                    {detailModal.Response.String}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
