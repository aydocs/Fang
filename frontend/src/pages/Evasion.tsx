import { useEffect, useState } from 'react'
import { bridge } from '../bridge'
import { Shield, RotateCw, Globe, UserCheck, Fingerprint, Clock, Save, CheckCircle, XCircle, Play } from 'lucide-react'

interface EvasionConfig {
  proxy_rotation: boolean
  proxy_list: string[]
  tor_enabled: boolean
  random_ua: boolean
  fingerprint: boolean
  adaptive_delay: boolean
  min_delay: number
  max_delay: number
}

const defaultConfig: EvasionConfig = {
  proxy_rotation: false,
  proxy_list: [],
  tor_enabled: false,
  random_ua: true,
  fingerprint: false,
  adaptive_delay: true,
  min_delay: 500000000,
  max_delay: 3000000000,
}

export default function Evasion() {
  const [cfg, setCfg] = useState<EvasionConfig>(defaultConfig)
  const [proxyText, setProxyText] = useState('')
  const [status, setStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [testStatus, setTestStatus] = useState<'idle' | 'testing' | 'ok' | 'fail'>('idle')

  useEffect(() => {
    bridge().GetEvasionConfig().then((data) => {
      try {
        const parsed = JSON.parse(data)
        if (parsed) {
          setCfg(parsed)
          setProxyText((parsed.proxy_list || []).join('\n'))
        }
      } catch {}
    }).catch(console.error)
  }, [])

  const update = <K extends keyof EvasionConfig>(key: K, value: EvasionConfig[K]) => {
    setCfg((prev) => ({ ...prev, [key]: value }))
  }

  const save = async () => {
    setStatus('saving')
    try {
      const updated = { ...cfg, proxy_list: proxyText.split('\n').filter((l) => l.trim()) }
      await bridge().SaveEvasionConfig(JSON.stringify(updated))
      setCfg(updated)
      setStatus('saved')
      setTimeout(() => setStatus('idle'), 2000)
    } catch {
      setStatus('error')
    }
  }

  const testConnection = async () => {
    setTestStatus('testing')
    try {
      await bridge().SaveEvasionConfig(JSON.stringify(cfg))
      setTestStatus('ok')
    } catch {
      setTestStatus('fail')
    }
    setTimeout(() => setTestStatus('idle'), 3000)
  }

  const statusIcon = (s: string) => {
    switch (s) {
      case 'saved': return <CheckCircle className="w-4 h-4 text-green-400" />
      case 'error': return <XCircle className="w-4 h-4 text-red-400" />
      default: return <Save className="w-3.5 h-3.5" />
    }
  }

  const minMs = Math.round(cfg.min_delay / 1000000)
  const maxMs = Math.round(cfg.max_delay / 1000000)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Evasion Configuration</h1>
        <div className="flex items-center gap-2">
          <button
            onClick={testConnection}
            disabled={testStatus === 'testing'}
            className="btn-ghost text-xs flex items-center gap-1"
          >
            <Play className="w-3.5 h-3.5" />
            {testStatus === 'testing' ? 'Testing...' : testStatus === 'ok' ? 'OK' : testStatus === 'fail' ? 'Failed' : 'Test'}
          </button>
          <button
            onClick={save}
            className={`btn-primary text-xs flex items-center gap-1 ${status === 'saved' ? 'bg-green-600' : ''}`}
          >
            {statusIcon(status)}
            {status === 'saving' ? 'Saving...' : status === 'saved' ? 'Saved!' : 'Save'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="card space-y-6">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Shield className="w-4 h-4" />
            Techniques
          </h2>

          <label className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <RotateCw className="w-4 h-4 text-gray-400" />
              <div>
                <p className="text-sm font-medium">Proxy Rotation</p>
                <p className="text-xs text-gray-500">Rotate proxies between requests</p>
              </div>
            </div>
            <input
              type="checkbox"
              className="toggle"
              checked={cfg.proxy_rotation}
              onChange={(e) => update('proxy_rotation', e.target.checked)}
            />
          </label>

          <label className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Globe className="w-4 h-4 text-gray-400" />
              <div>
                <p className="text-sm font-medium">Tor</p>
                <p className="text-xs text-gray-500">Route through Tor network (127.0.0.1:9050)</p>
              </div>
            </div>
            <input
              type="checkbox"
              className="toggle"
              checked={cfg.tor_enabled}
              onChange={(e) => update('tor_enabled', e.target.checked)}
            />
          </label>

          <label className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <UserCheck className="w-4 h-4 text-gray-400" />
              <div>
                <p className="text-sm font-medium">Random User-Agent</p>
                <p className="text-xs text-gray-500">Rotate user-agent headers</p>
              </div>
            </div>
            <input
              type="checkbox"
              className="toggle"
              checked={cfg.random_ua}
              onChange={(e) => update('random_ua', e.target.checked)}
            />
          </label>

          <label className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Fingerprint className="w-4 h-4 text-gray-400" />
              <div>
                <p className="text-sm font-medium">TLS Fingerprinting</p>
                <p className="text-xs text-gray-500">Spoof TLS fingerprint</p>
              </div>
            </div>
            <input
              type="checkbox"
              className="toggle"
              checked={cfg.fingerprint}
              onChange={(e) => update('fingerprint', e.target.checked)}
            />
          </label>

          <label className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Clock className="w-4 h-4 text-gray-400" />
              <div>
                <p className="text-sm font-medium">Adaptive Delay</p>
                <p className="text-xs text-gray-500">Mimic human browsing patterns</p>
              </div>
            </div>
            <input
              type="checkbox"
              className="toggle"
              checked={cfg.adaptive_delay}
              onChange={(e) => update('adaptive_delay', e.target.checked)}
            />
          </label>
        </div>

        <div className="space-y-6">
          <div className="card space-y-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Globe className="w-4 h-4" />
              Proxy List
            </h2>
            <textarea
              className="input w-full h-40 font-mono text-xs"
              placeholder="http://proxy1:8080&#10;http://proxy2:8080&#10;socks5://proxy3:1080"
              value={proxyText}
              onChange={(e) => setProxyText(e.target.value)}
            />
            <p className="text-xs text-gray-500">One proxy per line. Supported: http, https, socks5</p>
          </div>

          <div className="card space-y-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Clock className="w-4 h-4" />
              Delay Range
            </h2>
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Minimum: {minMs}ms</label>
              <input
                type="range"
                min="100"
                max="5000"
                step="100"
                value={minMs}
                onChange={(e) => update('min_delay', parseInt(e.target.value) * 1000000)}
                className="w-full"
              />
            </div>
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Maximum: {maxMs}ms</label>
              <input
                type="range"
                min="500"
                max="10000"
                step="100"
                value={maxMs}
                onChange={(e) => update('max_delay', parseInt(e.target.value) * 1000000)}
                className="w-full"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
