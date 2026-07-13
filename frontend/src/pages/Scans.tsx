import { useEffect, useState } from 'react'
import { bridge } from '../bridge'
import { ChevronDown, ChevronRight, FileText, Download, Trash2, FileDown, FileUp } from 'lucide-react'
import type { ScanRow, FindingRow } from '../types'

const statusColors: Record<string, string> = {
  running: 'text-blue-400 bg-blue-900/20',
  completed: 'text-green-400 bg-green-900/20',
  failed: 'text-red-400 bg-red-900/20',
  cancelled: 'text-yellow-400 bg-yellow-900/20',
  pending: 'text-gray-400 bg-gray-700/30',
}

export default function Scans() {
  const [scans, setScans] = useState<ScanRow[]>([])
  const [expanded, setExpanded] = useState<string | null>(null)
  const [findings, setFindings] = useState<FindingRow[]>([])
  const [exporting, setExporting] = useState<string | null>(null)

  const load = () => bridge().GetScans().then(setScans).catch(console.error)
  useEffect(() => {
    load()
    const iv = setInterval(load, 5000)
    return () => clearInterval(iv)
  }, [])

  const toggle = async (id: string) => {
    if (expanded === id) {
      setExpanded(null)
      return
    }
    setExpanded(id)
    try {
      const f = await bridge().GetScanFindings(id)
      setFindings(f)
    } catch (e: any) {
      console.error('Failed to load findings:', e)
    }
  }

  const downloadReport = async (scanID: string, format: string) => {
    setExporting(scanID)
    try {
      const path = await bridge().DownloadReport(scanID, format)
      if (path) {
        alert(`Report saved to: ${path}`)
      }
    } catch (e: any) {
      alert(`Download failed: ${e}`)
    }
    setExporting(null)
  }

  const exportReport = async (scanID: string, format: string) => {
    setExporting(scanID)
    try {
      const path = await bridge().GenerateReport(scanID, format)
      alert(`Report saved to: ${path}`)
    } catch (e: any) {
      alert(`Export failed: ${e}`)
    }
    setExporting(null)
  }

  const deleteScan = async (id: string) => {
    if (!confirm('Delete this scan and its findings?')) return
    try {
      await bridge().DeleteScan(id)
      load()
    } catch (e: any) {
      console.error('Failed to delete scan:', e)
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Scans</h1>

      <div className="space-y-2">
        {scans.map((s) => (
          <div key={s.ID}>
            <div
              className="card cursor-pointer hover:border-fang-400 transition-colors"
              onClick={() => toggle(s.ID)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {expanded === s.ID ? (
                    <ChevronDown className="w-4 h-4 text-gray-500" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-gray-500" />
                  )}
                  <div>
                    <p className="text-sm font-mono">{s.ID?.slice(0, 12)}...</p>
                    <p className="text-xs text-gray-500">{s.CreatedAt?.slice(0, 19)}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      statusColors[s.Status] || ''
                    }`}
                  >
                    {s.Status}
                  </span>
                  {s.Status === 'completed' && (
                    <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => downloadReport(s.ID, 'html')}
                        disabled={exporting === s.ID}
                        className="text-xs text-gray-400 hover:text-fang-300 px-2 py-1 rounded hover:bg-fang-700"
                        title="Download HTML report"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => exportReport(s.ID, 'json')}
                        disabled={exporting === s.ID}
                        className="text-xs text-gray-400 hover:text-fang-300 px-2 py-1 rounded hover:bg-fang-700"
                        title="Export JSON"
                      >
                        <FileDown className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => exportReport(s.ID, 'md')}
                        disabled={exporting === s.ID}
                        className="text-xs text-gray-400 hover:text-fang-300 px-2 py-1 rounded hover:bg-fang-700"
                        title="Export Markdown"
                      >
                        <FileText className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => deleteScan(s.ID)}
                        className="text-xs text-gray-400 hover:text-red-400 px-2 py-1 rounded hover:bg-fang-700"
                        title="Delete scan"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
            {expanded === s.ID && (
              <div className="ml-6 mt-2 space-y-1">
                {findings.length === 0 && (
                  <p className="text-sm text-gray-500 pl-4">No findings</p>
                )}
                {findings.map((f: FindingRow) => {
                  const url = f.URL?.String || ''
                  const evidence = f.Evidence?.String || ''
                  const severity = (f.Severity || '').toLowerCase()
                  return (
                    <div
                      key={f.ID}
                      className="bg-fang-700 rounded-lg p-3 border border-fang-600 text-sm"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium">{f.Title}</span>
                        <span className={`badge-${severity}`}>{f.Severity}</span>
                      </div>
                      <p className="text-xs text-gray-400 mt-1">
                        {f.ModuleID} {url ? `· ${url}` : ''}
                      </p>
                      {evidence && (
                        <pre className="text-xs text-gray-500 mt-1 bg-fang-900 p-2 rounded overflow-x-auto max-h-24">
                          {evidence}
                        </pre>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        ))}
        {scans.length === 0 && (
          <p className="text-gray-500 text-center py-8">No scans yet.</p>
        )}
      </div>
    </div>
  )
}
