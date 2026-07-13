import { useEffect, useState } from 'react'
import { bridge } from '../bridge'
import { Users, Trash2, UserPlus, Shield, ShieldOff } from 'lucide-react'
import type { UserRow } from '../types'

export default function UserManagement() {
  const [users, setUsers] = useState<UserRow[]>([])
  const [showForm, setShowForm] = useState(false)
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('user')

  const load = () => bridge().ListUsers().then(setUsers)

  useEffect(() => { load() }, [])

  const create = async () => {
    if (!username || !email || !password) return
    try {
      await bridge().RegisterUser(username, email, password, role)
      setUsername('')
      setEmail('')
      setPassword('')
      setRole('user')
      setShowForm(false)
      load()
    } catch (e: any) {
      alert('Failed: ' + e)
    }
  }

  const remove = async (id: string) => {
    if (!confirm('Delete this user?')) return
    await bridge().DeleteUser(id)
    load()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Users className="w-5 h-5" />
          User Management
        </h1>
        <button onClick={() => setShowForm(!showForm)} className="btn-primary flex items-center gap-2">
          <UserPlus className="w-4 h-4" />
          Add User
        </button>
      </div>

      {showForm && (
        <div className="card space-y-4">
          <h3 className="font-semibold">New User</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Username</label>
              <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Email</label>
              <input type="email" className="input" value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Password</label>
              <input type="password" className="input" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Role</label>
              <select className="input" value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="user">User</option>
                <option value="admin">Admin</option>
                <option value="readonly">Read Only</option>
              </select>
            </div>
          </div>
          <div className="flex gap-3">
            <button onClick={create} className="btn-primary flex items-center gap-2">
              <UserPlus className="w-4 h-4" />
              Create
            </button>
            <button onClick={() => setShowForm(false)} className="btn-ghost">Cancel</button>
          </div>
        </div>
      )}

      <div className="space-y-2">
        {users.map((u) => (
          <div key={u.ID} className="card flex items-center justify-between">
            <div className="flex items-center gap-3">
              {u.Role === 'admin' ? (
                <Shield className="w-5 h-5 text-fang-300" />
              ) : (
                <ShieldOff className="w-5 h-5 text-gray-500" />
              )}
              <div>
                <p className="font-medium">{u.Username}</p>
                <p className="text-xs text-gray-500">{u.Email} · {u.Role}</p>
              </div>
            </div>
            <button
              onClick={() => remove(u.ID)}
              className="btn-ghost text-xs"
              title="Delete user"
            >
              <Trash2 className="w-4 h-4 text-red-400" />
            </button>
          </div>
        ))}
        {users.length === 0 && (
          <p className="text-gray-500 text-center py-8">No users found.</p>
        )}
      </div>
    </div>
  )
}
