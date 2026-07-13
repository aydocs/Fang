import { useEffect, useState } from 'react'
import { bridge, onScanEvent, offScanEvent } from '../bridge'
import { Play, Loader2, Square, CheckCircle, AlertCircle } from 'lucide-react'
import type { ModuleInfo, ScanProgress } from '../types'

export default function Scanner() {
  const [url, setUrl] = useState('')
  const [modules, setModules] = useState<ModuleInfo[]>([])
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [result, setResult] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  useEffect(() => {
    bridge().ListModules().then(setModules).catch(console.error)
    bridge().GetActiveScan().then((id) => {
      if (id) {
        setScanning(true)
      }
    }).catch(console.error)
  }, [])

  useEffect(() => {
    onScanEvent('scan:started', (data: ScanProgress) => {
      setScanning(true)
      setProgress(data)
      setResult(null)
    })

    onScanEvent('scan:progress', (data: ScanProgress) => {
      setProgress(data)
    })

    onScanEvent('scan:completed', (data: ScanProgress) => {
      setProgress(data)
      setScanning(false)
      setResult({ type: 'success', message: data.message })
      setTimeout(() => setProgress(null), 3000)
    })

    onScanEvent('scan:error', (data: ScanProgress) => {
      setProgress(null)
      setScanning(false)
      setResult({ type: 'error', message: data.message })
    })

    onScanEvent('scan:cancelled', () => {
      setProgress(null)
      setScanning(false)
      setResult({ type: 'error', message: 'Scan cancelled' })
    })

    return () => {
      offScanEvent('scan:started')
      offScanEvent('scan:progress')
      offScanEvent('scan:completed')
      offScanEvent('scan:error')
      offScanEvent('scan:cancelled')
    }
  }, [])

  const toggle = (id: string) => {
    const next = new Set(selected)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelected(next)
  }

  const selectAll = () => {
    if (selected.size === modules.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(modules.map((m) => m.id)))
    }
  }

  const run = async () => {
    if (!url || scanning) return
    setResult(null)
    try {
      await bridge().RunScanAsync(url, Array.from(selected))
    } catch (e: any) {
      setResult({ type: 'error', message: String(e) })
    }
  }

  const cancel = async () => {
    try {
      await bridge().CancelScan()
    } catch (e: any) {
      console.error('Failed to cancel scan:', e)
    }
  }

  const percent = progress && progress.total > 0
    ? Math.round((progress.current / progress.total) * 100)
    : 0

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Scanner</h1>

      <div className="card space-y-4">
        <input
          className="input text-lg"
          placeholder="https://target.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={scanning}
        />

        <div>
          <div className="flex items-center justify-between mb-2">
            <p className="text-sm font-medium">
              Modules ({selected.size}/{modules.length} selected)
            </p>
            <button onClick={selectAll} className="text-xs text-fang-300 hover:text-fang-200">
              {selected.size === modules.length ? 'Deselect All' : 'Select All'}
            </button>
          </div>
          <div className="grid grid-cols-4 gap-2 max-h-60 overflow-y-auto">
            {modules.map((m) => (
              <button
                key={m.id}
                onClick={() => toggle(m.id)}
                disabled={scanning}
                className={`text-left p-2 rounded-lg text-xs border transition-colors ${
                  selected.has(m.id)
                    ? 'border-fang-300 bg-fang-600 text-white'
                    : 'border-fang-700 bg-fang-800 text-gray-400 hover:border-fang-500'
                } ${scanning ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                <p className="font-medium truncate">{m.id}</p>
                <p className="opacity-60 truncate">{m.severity}</p>
              </button>
            ))}
          </div>
        </div>

        {scanning && progress && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-400">{progress.message}</span>
              <span className="text-fang-300 font-medium">{percent}%</span>
            </div>
            <div className="w-full bg-fang-900 rounded-full h-2">
              <div
                className="bg-fang-400 h-2 rounded-full transition-all duration-300"
                style={{ width: `${percent}%` }}
              />
            </div>
            <p className="text-xs text-gray-500">
              {progress.current}/{progress.total} modules
            </p>
          </div>
        )}

        <div className="flex gap-3">
          {scanning ? (
            <button onClick={cancel} className="btn-danger flex items-center gap-2">
              <Square className="w-4 h-4" />
              Cancel Scan
            </button>
          ) : (
            <button
              onClick={run}
              disabled={!url}
              className="btn-primary flex items-center gap-2"
            >
              <Play className="w-4 h-4" />
              Start Scan
            </button>
          )}
        </div>

        {result && (
          <div
            className={`flex items-center gap-2 text-sm p-3 rounded-lg ${
              result.type === 'success'
                ? 'bg-green-900/30 text-green-300 border border-green-800'
                : 'bg-red-900/30 text-red-300 border border-red-800'
            }`}
          >
            {result.type === 'success' ? (
              <CheckCircle className="w-4 h-4" />
            ) : (
              <AlertCircle className="w-4 h-4" />
            )}
            {result.message}
          </div>
        )}
      </div>
    </div>
  )
}
