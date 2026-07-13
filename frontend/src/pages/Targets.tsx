import { useEffect, useState } from 'react'
import { bridge } from '../bridge'
import { Plus, Trash2, Globe } from 'lucide-react'
import type { TargetRow } from '../types'

export default function Targets() {
  const [targets, setTargets] = useState<TargetRow[]>([])
  const [newURL, setNewURL] = useState('')

  const load = () => bridge().GetTargets().then(setTargets).catch(console.error)

  useEffect(() => {
    load()
  }, [])

  const add = async () => {
    if (!newURL) return
    try {
      await bridge().CreateTarget(newURL)
      setNewURL('')
      load()
    } catch (e: any) {
      console.error('Failed to create target:', e)
    }
  }

  const remove = async (id: string) => {
    try {
      await bridge().DeleteTarget(id)
      load()
    } catch (e: any) {
      console.error('Failed to delete target:', e)
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Targets</h1>

      <form
        onSubmit={(e) => {
          e.preventDefault()
          add()
        }}
        className="flex gap-3"
      >
        <input
          className="input"
          placeholder="https://example.com"
          value={newURL}
          onChange={(e) => setNewURL(e.target.value)}
        />
        <button type="submit" className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          Add
        </button>
      </form>

      <div className="space-y-3">
        {targets.map((t) => (
          <div key={t.ID} className="card flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Globe className="w-5 h-5 text-fang-300" />
              <div>
                <p className="font-medium">{t.URL}</p>
                <p className="text-xs text-gray-500">{t.CreatedAt?.slice(0, 19)}</p>
              </div>
            </div>
            <button onClick={() => remove(t.ID)} className="btn-ghost text-xs">
              <Trash2 className="w-4 h-4 text-red-400" />
            </button>
          </div>
        ))}
        {targets.length === 0 && (
          <p className="text-gray-500 text-center py-8">No targets yet.</p>
        )}
      </div>
    </div>
  )
}
