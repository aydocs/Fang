import { useEffect, useState } from 'react'
import { bridge } from '../bridge'
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  CartesianGrid,
} from 'recharts'
import { Shield, Bug, ScanLine, AlertTriangle, TrendingUp } from 'lucide-react'
import type { SeverityStat, ModuleStat, ScanRow } from '../types'

const COLORS: Record<string, string> = {
  CRITICAL: '#f87171',
  HIGH: '#fb923c',
  MEDIUM: '#facc15',
  LOW: '#60a5fa',
  INFO: '#9ca3af',
}

export default function Dashboard() {
  const [stats, setStats] = useState({
    total_scans: 0,
    total_findings: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
  })
  const [severity, setSeverity] = useState<SeverityStat[]>([])
  const [modules, setModules] = useState<ModuleStat[]>([])
  const [scans, setScans] = useState<ScanRow[]>([])
  const [findingsOverTime, setFindingsOverTime] = useState<{ date: string; count: number }[]>([])

  const load = () => {
    bridge().GetStats().then(setStats).catch(console.error)
    bridge().GetSeverityStats().then(setSeverity).catch(console.error)
    bridge().GetModuleStats().then(setModules).catch(console.error)
    bridge().GetScans().then((scans) => {
      setScans(scans)
      const grouped: Record<string, number> = {}
      scans.forEach((s) => {
        if (s.CreatedAt) {
          const day = s.CreatedAt.slice(0, 10)
          grouped[day] = (grouped[day] || 0) + 1
        }
      })
      setFindingsOverTime(
        Object.entries(grouped).map(([date, count]) => ({ date, count })).slice(-14)
      )
    }).catch(console.error)
  }

  useEffect(() => {
    load()
    const iv = setInterval(load, 10000)
    return () => clearInterval(iv)
  }, [])

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>

      <div className="grid grid-cols-4 gap-4">
        {[
          { icon: Bug, label: 'Findings', value: stats.total_findings, color: 'text-blue-400' },
          { icon: ScanLine, label: 'Scans', value: stats.total_scans, color: 'text-green-400' },
          {
            icon: AlertTriangle,
            label: 'Critical',
            value: stats.critical_count,
            color: 'text-red-400',
          },
          {
            icon: Shield,
            label: 'High',
            value: stats.high_count,
            color: 'text-orange-400',
          },
        ].map((stat) => {
          const Icon = stat.icon
          return (
            <div key={stat.label} className="card">
              <div className="flex items-center gap-3">
                <Icon className={`w-8 h-8 ${stat.color}`} />
                <div>
                  <p className="text-2xl font-bold">{stat.value}</p>
                  <p className="text-xs text-gray-500">{stat.label}</p>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Findings by Severity</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={severity}>
              <XAxis dataKey="severity" stroke="#6b7280" />
              <YAxis stroke="#6b7280" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1a1a2e',
                  border: '1px solid #16213e',
                }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {severity.map((entry) => (
                  <Cell key={entry.severity} fill={COLORS[entry.severity] || '#9ca3af'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severity}
                dataKey="count"
                nameKey="severity"
                cx="50%"
                cy="50%"
                outerRadius={100}
                label={({ severity, count }) => `${severity}: ${count}`}
              >
                {severity.map((entry) => (
                  <Cell key={entry.severity} fill={COLORS[entry.severity] || '#9ca3af'} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {findingsOverTime.length > 1 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Scans Over Time</h2>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={findingsOverTime}>
              <CartesianGrid strokeDasharray="3 3" stroke="#16213e" />
              <XAxis dataKey="date" stroke="#6b7280" fontSize={11} />
              <YAxis stroke="#6b7280" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1a1a2e',
                  border: '1px solid #16213e',
                }}
              />
              <Line type="monotone" dataKey="count" stroke="#818cf8" strokeWidth={2} dot={{ fill: '#818cf8' }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Module Activity</h2>
        <div className="grid grid-cols-4 gap-3">
          {modules.slice(0, 24).map((m) => (
            <div key={m.module_id} className="bg-fang-700 rounded-lg p-3 text-center">
              <p className="text-sm font-medium">{m.module_id}</p>
              <p className="text-xs text-gray-500">{m.count} findings</p>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Recent Scans</h2>
        <div className="space-y-2">
          {scans.slice(0, 5).map((s) => (
            <div
              key={s.ID}
              className="flex items-center justify-between bg-fang-700 rounded-lg p-3 text-sm"
            >
              <div className="flex items-center gap-3">
                <TrendingUp className="w-4 h-4 text-gray-500" />
                <div>
                  <span className="font-mono text-xs">{s.ID?.slice(0, 8)}...</span>
                  <span className="text-xs text-gray-500 ml-3">{s.CreatedAt?.slice(0, 19)}</span>
                </div>
              </div>
              <span
                className={`text-xs px-2 py-0.5 rounded-full ${
                  s.Status === 'completed'
                    ? 'bg-green-900/50 text-green-300'
                    : s.Status === 'running'
                    ? 'bg-blue-900/50 text-blue-300'
                    : s.Status === 'failed'
                    ? 'bg-red-900/50 text-red-300'
                    : 'bg-gray-700 text-gray-400'
                }`}
              >
                {s.Status}
              </span>
            </div>
          ))}
          {scans.length === 0 && (
            <p className="text-gray-500 text-center py-4 text-sm">No scans yet</p>
          )}
        </div>
      </div>
    </div>
  )
}
