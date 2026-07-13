import { useEffect, useState, type ComponentType } from 'react'
import { bridge } from '../bridge'
import { Bell, Trash2, Check, Filter, AlertTriangle, CheckCircle, Info, XCircle, Loader2 } from 'lucide-react'
import type { NotificationRow } from '../types'

const typeConfig: Record<string, { icon: ComponentType<{ className?: string }>; color: string }> = {
  scan_complete: { icon: CheckCircle, color: 'text-green-400 bg-green-900/30' },
  scan_error: { icon: XCircle, color: 'text-red-400 bg-red-900/30' },
  scan_started: { icon: Loader2, color: 'text-blue-400 bg-blue-900/30' },
  finding_critical: { icon: AlertTriangle, color: 'text-red-400 bg-red-900/30' },
  finding_high: { icon: AlertTriangle, color: 'text-orange-400 bg-orange-900/30' },
  info: { icon: Info, color: 'text-gray-400 bg-gray-700/30' },
}

const filterOptions = [
  { value: 'all', label: 'All' },
  { value: 'scan_complete', label: 'Scan Complete' },
  { value: 'scan_error', label: 'Scan Error' },
  { value: 'scan_started', label: 'Scan Started' },
  { value: 'finding_critical', label: 'Critical Findings' },
  { value: 'finding_high', label: 'High Findings' },
]

export default function Notifications() {
  const [notifications, setNotifications] = useState<NotificationRow[]>([])
  const [filter, setFilter] = useState('all')
  const [showUnreadOnly, setShowUnreadOnly] = useState(false)

  const load = () => bridge().GetNotifications().then(setNotifications)

  useEffect(() => {
    load()
    const iv = setInterval(load, 5000)
    return () => clearInterval(iv)
  }, [])

  const markRead = async (id: string) => {
    await bridge().MarkNotificationRead(id)
    load()
  }

  const remove = async (id: string) => {
    await bridge().DeleteNotification(id)
    load()
  }

  const markAllRead = async () => {
    for (const n of notifications) {
      if (!n.Read) {
        try { await bridge().MarkNotificationRead(n.ID) } catch {}
      }
    }
    load()
  }

  const clearAll = async () => {
    if (!confirm('Delete all notifications?')) return
    for (const n of notifications) {
      try { await bridge().DeleteNotification(n.ID) } catch {}
    }
    load()
  }

  const filtered = notifications.filter((n) => {
    if (filter !== 'all' && n.Type !== filter) return false
    if (showUnreadOnly && n.Read) return false
    return true
  })

  const unreadCount = notifications.filter((n) => !n.Read).length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Bell className="w-5 h-5" />
          Notifications
          {unreadCount > 0 && (
            <span className="text-sm bg-fang-600 text-white px-2 py-0.5 rounded-full">
              {unreadCount}
            </span>
          )}
        </h1>
        <div className="flex items-center gap-2">
          <button onClick={markAllRead} className="btn-ghost text-xs">Mark All Read</button>
          <button onClick={clearAll} className="btn-ghost text-xs text-red-400">Clear All</button>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <Filter className="w-4 h-4 text-gray-500" />
        <select
          className="input w-auto"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        >
          {filterOptions.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
        <label className="flex items-center gap-2 text-sm text-gray-400">
          <input
            type="checkbox"
            checked={showUnreadOnly}
            onChange={(e) => setShowUnreadOnly(e.target.checked)}
            className="rounded bg-fang-900 border-fang-600"
          />
          Unread only
        </label>
      </div>

      <div className="space-y-2">
        {filtered.map((n) => {
          const cfg = typeConfig[n.Type] || { icon: Bell, color: 'text-gray-400 bg-gray-700/30' }
          const Icon = cfg.icon

          return (
            <div
              key={n.ID}
              className={`card flex items-center justify-between transition-opacity ${
                n.Read ? 'opacity-50' : 'border-l-4 border-l-fang-400'
              }`}
            >
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${cfg.color}`}>
                  <Icon className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium text-sm">{n.Title}</p>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${cfg.color}`}>
                      {n.Type.replace('_', ' ')}
                    </span>
                  </div>
                {n.Message?.Valid && n.Message.String && (
                  <p className="text-xs text-gray-400 mt-0.5">{n.Message.String}</p>
                )}
                  <p className="text-xs text-gray-500 mt-0.5">
                    {n.CreatedAt?.slice(0, 19)}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1">
                {!n.Read && (
                  <button
                    onClick={() => markRead(n.ID)}
                    className="text-xs text-gray-400 hover:text-green-400 px-2 py-1 rounded hover:bg-fang-700"
                    title="Mark as read"
                  >
                    <Check className="w-4 h-4" />
                  </button>
                )}
                <button
                  onClick={() => remove(n.ID)}
                  className="text-xs text-gray-400 hover:text-red-400 px-2 py-1 rounded hover:bg-fang-700"
                  title="Delete"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          )
        })}
        {filtered.length === 0 && (
          <div className="card flex items-center gap-3 text-gray-400">
            <Bell className="w-5 h-5" />
            <p>No notifications match the current filter.</p>
          </div>
        )}
      </div>
    </div>
  )
}
