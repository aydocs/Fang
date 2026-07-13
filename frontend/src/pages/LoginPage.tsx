import { useState } from 'react'
import { bridge } from '../bridge'
import { Shield, LogIn, UserPlus, AlertCircle } from 'lucide-react'

interface Props {
  onLogin: (user: { user_id: string; username: string; role: string }) => void
}

export default function LoginPage({ onLogin }: Props) {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      if (mode === 'login') {
        const result = await bridge().Login(username, password)
        if (result.success) {
          onLogin({ user_id: result.user_id, username: result.username, role: result.role })
        } else {
          setError(result.error || 'Login failed')
        }
      } else {
        await bridge().RegisterUser(username, email, password, 'user')
        const result = await bridge().Login(username, password)
        if (result.success) {
          onLogin({ user_id: result.user_id, username: result.username, role: result.role })
        } else {
          setError('Registration succeeded but login failed')
        }
      }
    } catch (e: any) {
      setError(String(e))
    }
    setLoading(false)
  }

  return (
    <div className="h-screen flex items-center justify-center bg-fang-900">
      <div className="w-full max-w-sm">
        <div className="card space-y-6">
          <div className="text-center space-y-2">
            <Shield className="w-12 h-12 text-fang-300 mx-auto" />
            <h1 className="text-2xl font-bold">FANG</h1>
            <p className="text-sm text-gray-500">Security Scanner</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Username</label>
              <input
                className="input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoFocus
              />
            </div>

            {mode === 'register' && (
              <div>
                <label className="text-sm text-gray-400 mb-1 block">Email</label>
                <input
                  type="email"
                  className="input"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
            )}

            <div>
              <label className="text-sm text-gray-400 mb-1 block">Password</label>
              <input
                type="password"
                className="input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            {error && (
              <div className="flex items-center gap-2 text-sm text-red-400 bg-red-900/30 p-3 rounded-lg border border-red-800">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full flex items-center justify-center gap-2"
            >
              {mode === 'login' ? (
                <><LogIn className="w-4 h-4" /> Sign In</>
              ) : (
                <><UserPlus className="w-4 h-4" /> Register</>
              )}
            </button>
          </form>

          <div className="text-center">
            <button
              onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError('') }}
              className="text-xs text-fang-300 hover:text-fang-200"
            >
              {mode === 'login' ? "Don't have an account? Register" : 'Already have an account? Sign In'}
            </button>
          </div>

        </div>
      </div>
    </div>
  )
}
