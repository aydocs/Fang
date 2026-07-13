import { useState, useEffect, type ComponentType } from 'react'
import { WindowMinimise, WindowToggleMaximise, Quit } from '../wailsjs/runtime/runtime'
import {
  Shield,
  Target,
  ScanLine,
  Bug,
  Clock,
  Bell,
  Activity,
  Search,
  Settings,
  ChevronDown,
  ChevronUp,
  X,
  LogOut,
  Users,
  Building2,
  GitBranch,
  Workflow,
  Eye,
} from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Targets from './pages/Targets'
import Scanner from './pages/Scanner'
import Scans from './pages/Scans'
import Findings from './pages/Findings'
import Schedules from './pages/Schedules'
import Notifications from './pages/Notifications'
import SettingsPage from './pages/SettingsPage'
import LoginPage from './pages/LoginPage'
import UserManagement from './pages/UserManagement'
import Organizations from './pages/Organizations'
import Integrations from './pages/Integrations'
import Workflows from './pages/Workflows'
import Evasion from './pages/Evasion'
import { bridge } from './bridge'

type Tab =
  | 'dashboard'
  | 'targets'
  | 'scanner'
  | 'scans'
  | 'findings'
  | 'schedules'
  | 'workflows'
  | 'notifications'
  | 'integrations'
  | 'evasion'
  | 'settings'
  | 'users'
  | 'orgs'

interface User {
  user_id: string
  username: string
  role: string
}

const tabs: { id: Tab; label: string; icon: ComponentType<{ className?: string }> }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: Activity },
  { id: 'scanner', label: 'Scanner', icon: Search },
  { id: 'targets', label: 'Targets', icon: Target },
  { id: 'scans', label: 'Scans', icon: ScanLine },
  { id: 'findings', label: 'Findings', icon: Bug },
  { id: 'schedules', label: 'Schedules', icon: Clock },
  { id: 'workflows', label: 'Workflows', icon: Workflow },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'integrations', label: 'Integrations', icon: GitBranch },
  { id: 'evasion', label: 'Evasion', icon: Eye },
  { id: 'users', label: 'Users', icon: Users },
  { id: 'orgs', label: 'Orgs', icon: Building2 },
  { id: 'settings', label: 'Settings', icon: Settings },
]

export default function App() {
  const [user, setUser] = useState<User | null>(null)
  const [activeTab, setActiveTab] = useState<Tab>('dashboard')
  const [language, setLanguage] = useState('en')

  useEffect(() => {
    bridge().GetLanguage().then(setLanguage).catch(() => {})
  }, [])

  if (!user) {
    return <LoginPage onLogin={(u) => setUser(u)} />
  }

  return (
    <div className="h-screen flex flex-col select-none">
      <header className="bg-fang-800 border-b border-fang-600 px-4 py-2 flex items-center justify-between drag">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-fang-300" />
          <h1 className="text-sm font-bold tracking-wider">FANG</h1>
          <span className="text-xs text-gray-500">Security Scanner</span>
        </div>
        <div className="flex items-center gap-2 no-drag">
          <span className="text-xs text-gray-500">{user.username}</span>
          <button
            onClick={() => setUser(null)}
            className="w-7 h-7 flex items-center justify-center rounded hover:bg-fang-700 text-gray-400 hover:text-red-400 transition-colors"
            title="Logout"
          >
            <LogOut className="w-4 h-4" />
          </button>
          <button
            onClick={WindowMinimise}
            className="w-8 h-8 flex items-center justify-center rounded hover:bg-fang-700 text-gray-400 hover:text-white transition-colors"
          >
            <ChevronDown className="w-4 h-4" />
          </button>
          <button
            onClick={WindowToggleMaximise}
            className="w-8 h-8 flex items-center justify-center rounded hover:bg-fang-700 text-gray-400 hover:text-white transition-colors"
          >
            <ChevronUp className="w-4 h-4" />
          </button>
          <button
            onClick={Quit}
            className="w-8 h-8 flex items-center justify-center rounded hover:bg-red-600 text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        <nav className="w-48 bg-fang-800 border-r border-fang-600 flex flex-col p-2 gap-0.5">
          {tabs.map((tab) => {
            const Icon = tab.icon
            const active = activeTab === tab.id
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors text-left ${
                  active
                    ? 'bg-fang-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-fang-700'
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            )
          })}
        </nav>

        <main className="flex-1 overflow-auto p-6">
          {activeTab === 'dashboard' && <Dashboard />}
          {activeTab === 'scanner' && <Scanner />}
          {activeTab === 'targets' && <Targets />}
          {activeTab === 'scans' && <Scans />}
          {activeTab === 'findings' && <Findings />}
          {activeTab === 'schedules' && <Schedules />}
          {activeTab === 'workflows' && <Workflows />}
          {activeTab === 'notifications' && <Notifications />}
          {activeTab === 'integrations' && <Integrations />}
          {activeTab === 'evasion' && <Evasion />}
          {activeTab === 'users' && <UserManagement />}
          {activeTab === 'orgs' && <Organizations />}
          {activeTab === 'settings' && <SettingsPage />}
        </main>
      </div>
    </div>
  )
}
