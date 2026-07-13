import { useEffect, useState } from 'react'
import { bridge } from '../bridge'
import { Clock, Trash2, Plus, Play } from 'lucide-react'
import type { ScheduleRow, TargetRow } from '../types'

export default function Schedules() {
  const [schedules, setSchedules] = useState<ScheduleRow[]>([])
  const [targets, setTargets] = useState<TargetRow[]>([])
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    target_id: '',
    name: '',
    cron_expr: '',
    modules: '',
    notify_on: 'critical',
    webhook_url: '',
  })

  const load = () => {
    bridge().GetSchedules().then(setSchedules).catch(console.error)
    bridge().GetTargets().then(setTargets).catch(console.error)
  }

  useEffect(() => {
    load()
  }, [])

  const create = async () => {
    if (!form.target_id || !form.cron_expr) return
    try {
      await bridge().CreateSchedule(form)
      setForm({
        target_id: '',
        name: '',
        cron_expr: '',
        modules: '',
        notify_on: 'critical',
        webhook_url: '',
      })
      setShowForm(false)
      load()
    } catch (e: any) {
      alert(`Failed: ${e}`)
    }
  }

  const remove = async (id: string) => {
    try {
      await bridge().DeleteSchedule(id)
      load()
    } catch (e: any) {
      console.error('Failed to delete schedule:', e)
    }
  }

  const presets = [
    { label: 'Every hour', expr: '0 * * * * *' },
    { label: 'Every 6 hours', expr: '0 */6 * * * *' },
    { label: 'Daily', expr: '0 0 8 * * *' },
    { label: 'Weekly', expr: '0 0 8 * * 1' },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Schedules</h1>
        <button onClick={() => setShowForm(!showForm)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          New Schedule
        </button>
      </div>

      {showForm && (
        <div className="card space-y-4">
          <h3 className="font-semibold">Create Schedule</h3>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Target</label>
              <select
                className="input"
                value={form.target_id}
                onChange={(e) => setForm({ ...form, target_id: e.target.value })}
              >
                <option value="">Select target...</option>
                {targets.map((t) => (
                  <option key={t.ID} value={t.ID}>
                    {t.URL}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-sm text-gray-400 mb-1 block">Name</label>
              <input
                className="input"
                placeholder="My scan schedule"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </div>
          </div>

          <div>
            <label className="text-sm text-gray-400 mb-1 block">Cron Expression (with seconds)</label>
            <input
              className="input font-mono"
              placeholder="0 */6 * * * *"
              value={form.cron_expr}
              onChange={(e) => setForm({ ...form, cron_expr: e.target.value })}
            />
            <div className="flex gap-2 mt-2">
              {presets.map((p) => (
                <button
                  key={p.expr}
                  onClick={() => setForm({ ...form, cron_expr: p.expr })}
                  className="text-xs px-2 py-1 bg-fang-700 rounded hover:bg-fang-600 text-gray-300"
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex gap-3">
            <button onClick={create} className="btn-primary flex items-center gap-2">
              <Clock className="w-4 h-4" />
              Create
            </button>
            <button onClick={() => setShowForm(false)} className="btn-ghost">
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {schedules.map((s) => (
          <div key={s.ID} className="card flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Clock className="w-5 h-5 text-fang-300" />
              <div>
                <p className="font-medium">{s.Name || s.ID.slice(0, 8)}</p>
                <p className="text-xs text-gray-500 font-mono">{s.CronExpr}</p>
                <p className="text-xs text-gray-500">
                  Notify on: {s.NotifyOn} {s.WebhookURL ? `· Webhook: ${s.WebhookURL}` : ''}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs px-2 py-0.5 rounded-full bg-green-900/50 text-green-300">
                active
              </span>
              <button onClick={() => remove(s.ID)} className="btn-ghost text-xs">
                <Trash2 className="w-4 h-4 text-red-400" />
              </button>
            </div>
          </div>
        ))}
        {schedules.length === 0 && !showForm && (
          <div className="card flex items-center gap-3 text-gray-400">
            <Clock className="w-5 h-5" />
            <p>No scheduled scans yet. Create one to get started.</p>
          </div>
        )}
      </div>
    </div>
  )
}
