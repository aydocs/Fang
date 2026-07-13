import { useEffect, useState } from 'react'
import { bridge } from '../bridge'
import { GitBranch, Ticket, ExternalLink, Save, CheckCircle, XCircle } from 'lucide-react'
import type { JiraConfig, GitHubConfig, SlackConfig } from '../types'

export default function Integrations() {
  const [jira, setJira] = useState<JiraConfig>({ url: '', username: '', api_token: '', project: '', issue_type: 'Bug' })
  const [github, setGitHub] = useState<GitHubConfig>({ token: '', owner: '', repo: '' })
  const [slack, setSlack] = useState<SlackConfig>({ webhook_url: '' })
  const [jiraStatus, setJiraStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [githubStatus, setGitHubStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [slackStatus, setSlackStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [jiraTestStatus, setJiraTestStatus] = useState<'idle' | 'testing' | 'ok' | 'fail'>('idle')
  const [githubTestStatus, setGitHubTestStatus] = useState<'idle' | 'testing' | 'ok' | 'fail'>('idle')

  useEffect(() => {
    Promise.all([
      bridge().GetIntegrationConfig('jira'),
      bridge().GetIntegrationConfig('github'),
      bridge().GetIntegrationConfig('slack'),
    ]).then(([j, g, s]) => {
      try {
        const jc = JSON.parse(j)
        if (jc.url) setJira(jc)
      } catch {}
      try {
        const gc = JSON.parse(g)
        if (gc.token) setGitHub(gc)
      } catch {}
      try {
        const sc = JSON.parse(s)
        if (sc.webhook_url) setSlack(sc)
      } catch {}
    }).catch(console.error)
  }, [])

  const saveJira = async () => {
    setJiraStatus('saving')
    try {
      await bridge().ConfigureIntegration('jira', JSON.stringify(jira))
      setJiraStatus('saved')
      setTimeout(() => setJiraStatus('idle'), 2000)
    } catch {
      setJiraStatus('error')
    }
  }

  const saveGitHub = async () => {
    setGitHubStatus('saving')
    try {
      await bridge().ConfigureIntegration('github', JSON.stringify(github))
      setGitHubStatus('saved')
      setTimeout(() => setGitHubStatus('idle'), 2000)
    } catch {
      setGitHubStatus('error')
    }
  }

  const saveSlack = async () => {
    setSlackStatus('saving')
    try {
      await bridge().ConfigureIntegration('slack', JSON.stringify(slack))
      setSlackStatus('saved')
      setTimeout(() => setSlackStatus('idle'), 2000)
    } catch {
      setSlackStatus('error')
    }
  }

  const testJira = async () => {
    setJiraTestStatus('testing')
    try {
      await bridge().ConfigureIntegration('jira', JSON.stringify(jira))
      const resp = await bridge().CreateJiraIssue('', '')
      if (resp) {
        setJiraTestStatus('fail')
      } else {
        setJiraTestStatus('ok')
      }
    } catch {
      setJiraTestStatus('ok')
    }
    setTimeout(() => setJiraTestStatus('idle'), 3000)
  }

  const testGitHub = async () => {
    setGitHubTestStatus('testing')
    try {
      await bridge().ConfigureIntegration('github', JSON.stringify(github))
      const resp = await bridge().CreateGitHubIssue('', '')
      if (resp) {
        setGitHubTestStatus('fail')
      } else {
        setGitHubTestStatus('ok')
      }
    } catch {
      setGitHubTestStatus('ok')
    }
    setTimeout(() => setGitHubTestStatus('idle'), 3000)
  }

  const statusIcon = (status: string) => {
    switch (status) {
      case 'saved': return <CheckCircle className="w-4 h-4 text-green-400" />
      case 'error': return <XCircle className="w-4 h-4 text-red-400" />
      default: return <Save className="w-3.5 h-3.5" />
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Integrations</h1>

      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Ticket className="w-4 h-4" />
            Jira
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={testJira}
              disabled={jiraTestStatus === 'testing' || !jira.url}
              className="btn-ghost text-xs flex items-center gap-1"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              {jiraTestStatus === 'testing' ? 'Testing...' : jiraTestStatus === 'ok' ? 'OK' : jiraTestStatus === 'fail' ? 'Failed' : 'Test'}
            </button>
            <button
              onClick={saveJira}
              className={`btn-primary text-xs flex items-center gap-1 ${jiraStatus === 'saved' ? 'bg-green-600' : ''}`}
            >
              {statusIcon(jiraStatus)}
              {jiraStatus === 'saving' ? 'Saving...' : jiraStatus === 'saved' ? 'Saved!' : 'Save'}
            </button>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-sm text-gray-400 mb-1 block">URL</label>
            <input className="input" placeholder="https://your-domain.atlassian.net" value={jira.url} onChange={(e) => setJira({ ...jira, url: e.target.value })} />
          </div>
          <div>
            <label className="text-sm text-gray-400 mb-1 block">Issue Type</label>
            <select className="input" value={jira.issue_type} onChange={(e) => setJira({ ...jira, issue_type: e.target.value })}>
              <option value="Bug">Bug</option>
              <option value="Task">Task</option>
              <option value="Story">Story</option>
              <option value="Improvement">Improvement</option>
            </select>
          </div>
          <div>
            <label className="text-sm text-gray-400 mb-1 block">Username (Email)</label>
            <input className="input" placeholder="user@example.com" value={jira.username} onChange={(e) => setJira({ ...jira, username: e.target.value })} />
          </div>
          <div>
            <label className="text-sm text-gray-400 mb-1 block">API Token</label>
            <input className="input" type="password" placeholder="API token" value={jira.api_token} onChange={(e) => setJira({ ...jira, api_token: e.target.value })} />
          </div>
          <div>
            <label className="text-sm text-gray-400 mb-1 block">Project Key</label>
            <input className="input" placeholder="PROJ" value={jira.project} onChange={(e) => setJira({ ...jira, project: e.target.value })} />
          </div>
        </div>
      </div>

      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <GitBranch className="w-4 h-4" />
            GitHub
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={testGitHub}
              disabled={githubTestStatus === 'testing' || !github.token}
              className="btn-ghost text-xs flex items-center gap-1"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              {githubTestStatus === 'testing' ? 'Testing...' : githubTestStatus === 'ok' ? 'OK' : githubTestStatus === 'fail' ? 'Failed' : 'Test'}
            </button>
            <button
              onClick={saveGitHub}
              className={`btn-primary text-xs flex items-center gap-1 ${githubStatus === 'saved' ? 'bg-green-600' : ''}`}
            >
              {statusIcon(githubStatus)}
              {githubStatus === 'saving' ? 'Saving...' : githubStatus === 'saved' ? 'Saved!' : 'Save'}
            </button>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-sm text-gray-400 mb-1 block">Token</label>
            <input className="input" type="password" placeholder="ghp_..." value={github.token} onChange={(e) => setGitHub({ ...github, token: e.target.value })} />
          </div>
          <div>
            <label className="text-sm text-gray-400 mb-1 block">Owner</label>
            <input className="input" placeholder="owner or organization" value={github.owner} onChange={(e) => setGitHub({ ...github, owner: e.target.value })} />
          </div>
          <div>
            <label className="text-sm text-gray-400 mb-1 block">Repository</label>
            <input className="input" placeholder="repo-name" value={github.repo} onChange={(e) => setGitHub({ ...github, repo: e.target.value })} />
          </div>
        </div>
      </div>

      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <ExternalLink className="w-4 h-4" />
            Slack Notifications
          </h2>
          <button
            onClick={saveSlack}
            className={`btn-primary text-xs flex items-center gap-1 ${slackStatus === 'saved' ? 'bg-green-600' : ''}`}
          >
            {statusIcon(slackStatus)}
            {slackStatus === 'saving' ? 'Saving...' : slackStatus === 'saved' ? 'Saved!' : 'Save'}
          </button>
        </div>
        <div>
          <label className="text-sm text-gray-400 mb-1 block">Webhook URL</label>
          <input className="input w-full" placeholder="https://hooks.slack.com/services/..." value={slack.webhook_url} onChange={(e) => setSlack({ ...slack, webhook_url: e.target.value })} />
        </div>
      </div>
    </div>
  )
}
