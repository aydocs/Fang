import { useEffect, useState } from 'react'
import { bridge } from '../bridge'
import { Workflow, Play, ToggleLeft, ToggleRight, Plus, Trash2 } from 'lucide-react'
import type { Workflow as WorkflowType, WorkflowAction } from '../types'

const triggerOptions = [
  'scan_complete',
  'finding_found',
  'severity_met',
  'schedule',
  'new_target',
]

const actionTypeOptions = [
  'webhook',
  'slack_notify',
  'email_notify',
  'jira_issue',
  'github_issue',
  'script_exec',
  'notification',
]

export default function Workflows() {
  const [workflows, setWorkflows] = useState<WorkflowType[]>([])
  const [showCreate, setShowCreate] = useState(false)
  const [name, setName] = useState('')
  const [triggerType, setTriggerType] = useState('scan_complete')
  const [conditions, setConditions] = useState<Record<string, string>>({})
  const [actions, setActions] = useState<WorkflowAction[]>([])
  const [newConditionKey, setNewConditionKey] = useState('')
  const [newConditionVal, setNewConditionVal] = useState('')
  const [testMsg, setTestMsg] = useState('')

  useEffect(() => {
    loadWorkflows()
  }, [])

  const loadWorkflows = async () => {
    try {
      const list = await bridge().ListWorkflows()
      setWorkflows(list)
    } catch (e) {
      console.error(e)
    }
  }

  const handleCreate = async () => {
    try {
      const condStr = JSON.stringify(conditions)
      const actStr = JSON.stringify(actions)
      await bridge().CreateWorkflow(name, triggerType, condStr, actStr)
      setShowCreate(false)
      setName('')
      setTriggerType('scan_complete')
      setConditions({})
      setActions([])
      setTestMsg('')
      await loadWorkflows()
    } catch (e) {
      setTestMsg(`Error: ${e}`)
    }
  }

  const handleDelete = async (id: string) => {
    await bridge().DeleteWorkflow(id)
    await loadWorkflows()
  }

  const handleToggle = async (id: string, enabled: boolean) => {
    await bridge().ToggleWorkflow(id, enabled)
    await loadWorkflows()
  }

  const handleTest = async (id: string) => {
    try {
      const msg = await bridge().TestWorkflow(id)
      setTestMsg(msg)
      setTimeout(() => setTestMsg(''), 4000)
    } catch (e) {
      setTestMsg(`Error: ${e}`)
    }
  }

  const addCondition = () => {
    if (newConditionKey && newConditionVal) {
      setConditions({ ...conditions, [newConditionKey]: newConditionVal })
      setNewConditionKey('')
      setNewConditionVal('')
    }
  }

  const removeCondition = (key: string) => {
    const next = { ...conditions }
    delete next[key]
    setConditions(next)
  }

  const addAction = () => {
    setActions([...actions, { type: 'webhook', config: {} }])
  }

  const updateActionType = (i: number, t: string) => {
    const next = [...actions]
    next[i] = { type: t, config: {} }
    setActions(next)
  }

  const updateActionConfig = (i: number, key: string, value: string) => {
    const next = [...actions]
    next[i] = { ...next[i], config: { ...next[i].config, [key]: value } }
    setActions(next)
  }

  const removeAction = (i: number) => {
    setActions(actions.filter((_, idx) => idx !== i))
  }

  const actionConfigFields = (action: WorkflowAction): { key: string; label: string; placeholder: string }[] => {
    switch (action.type) {
      case 'webhook':
        return [
          { key: 'url', label: 'URL', placeholder: 'https://example.com/hook' },
          { key: 'method', label: 'Method', placeholder: 'POST' },
        ]
      case 'slack_notify':
        return [
          { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/...' },
          { key: 'message', label: 'Message', placeholder: 'Notification text' },
        ]
      case 'email_notify':
        return [
          { key: 'to', label: 'To', placeholder: 'user@example.com' },
          { key: 'subject', label: 'Subject', placeholder: 'Alert' },
          { key: 'message', label: 'Message', placeholder: 'Body text' },
        ]
      case 'jira_issue':
        return [
          { key: 'summary', label: 'Summary', placeholder: 'Issue title' },
          { key: 'description', label: 'Description', placeholder: 'Issue body' },
        ]
      case 'github_issue':
        return [
          { key: 'title', label: 'Title', placeholder: 'Issue title' },
          { key: 'body', label: 'Body', placeholder: 'Issue body' },
        ]
      case 'script_exec':
        return [
          { key: 'command', label: 'Command', placeholder: './script.sh' },
        ]
      case 'notification':
        return [
          { key: 'title', label: 'Title', placeholder: 'Notification title' },
          { key: 'message', label: 'Message', placeholder: 'Notification message' },
          { key: 'type', label: 'Type', placeholder: 'workflow' },
        ]
      default:
        return []
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Workflows</h1>
        <button onClick={() => setShowCreate(true)} className="btn-primary text-sm flex items-center gap-2">
          <Plus className="w-4 h-4" />
          Create Workflow
        </button>
      </div>

      {testMsg && (
        <div className="bg-fang-700 border border-fang-500 rounded-lg px-4 py-2 text-sm text-gray-200">
          {testMsg}
        </div>
      )}

      {showCreate && (
        <div className="card space-y-4">
          <h2 className="text-lg font-semibold">New Workflow</h2>
          <div>
            <label className="text-sm text-gray-400 mb-1 block">Name</label>
            <input className="input w-full" value={name} onChange={(e) => setName(e.target.value)} placeholder="My Workflow" />
          </div>
          <div>
            <label className="text-sm text-gray-400 mb-1 block">Trigger Type</label>
            <select className="input w-full" value={triggerType} onChange={(e) => setTriggerType(e.target.value)}>
              {triggerOptions.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-sm text-gray-400 mb-1 block">Conditions (key=value)</label>
            <div className="flex gap-2 mb-2">
              <input className="input flex-1" value={newConditionKey} onChange={(e) => setNewConditionKey(e.target.value)} placeholder="Key" />
              <input className="input flex-1" value={newConditionVal} onChange={(e) => setNewConditionVal(e.target.value)} placeholder="Value" />
              <button onClick={addCondition} className="btn-primary text-xs">Add</button>
            </div>
            {Object.entries(conditions).map(([k, v]) => (
              <div key={k} className="flex items-center gap-2 text-sm text-gray-300 mb-1">
                <span className="bg-fang-700 px-2 py-0.5 rounded">{k}={v}</span>
                <button onClick={() => removeCondition(k)} className="text-red-400 hover:text-red-300">
                  <Trash2 className="w-3 h-3" />
                </button>
              </div>
            ))}
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-sm text-gray-400">Actions</label>
              <button onClick={addAction} className="btn-ghost text-xs flex items-center gap-1">
                <Plus className="w-3 h-3" />
                Add Action
              </button>
            </div>
            {actions.map((action, i) => (
              <div key={i} className="bg-fang-700 rounded-lg p-3 mb-2 space-y-2">
                <div className="flex items-center justify-between">
                  <select className="input text-sm" value={action.type} onChange={(e) => updateActionType(i, e.target.value)}>
                    {actionTypeOptions.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                  <button onClick={() => removeAction(i)} className="text-red-400 hover:text-red-300 ml-2">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
                {actionConfigFields(action).map((field) => (
                  <div key={field.key}>
                    <label className="text-xs text-gray-500 mb-0.5 block">{field.label}</label>
                    <input
                      className="input text-sm w-full"
                      value={action.config[field.key] || ''}
                      onChange={(e) => updateActionConfig(i, field.key, e.target.value)}
                      placeholder={field.placeholder}
                    />
                  </div>
                ))}
              </div>
            ))}
          </div>

          <div className="flex gap-2 justify-end">
            <button onClick={() => setShowCreate(false)} className="btn-ghost text-sm">Cancel</button>
            <button onClick={handleCreate} className="btn-primary text-sm" disabled={!name}>Create</button>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {workflows.map((wf) => (
          <div key={wf.id} className="card flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Workflow className="w-5 h-5 text-fang-300" />
              <div>
                <span className="font-medium">{wf.name}</span>
                <span className="text-xs text-gray-500 ml-2">trigger: {wf.trigger.type}</span>
                <span className="text-xs text-gray-500 ml-2">actions: {wf.actions.length}</span>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleTest(wf.id)}
                className="btn-ghost text-xs flex items-center gap-1"
                title="Test Run"
              >
                <Play className="w-3.5 h-3.5" />
                Test
              </button>
              <button
                onClick={() => handleToggle(wf.id, !wf.enabled)}
                className="btn-ghost text-xs flex items-center gap-1"
                title={wf.enabled ? 'Disable' : 'Enable'}
              >
                {wf.enabled ? <ToggleRight className="w-4 h-4 text-green-400" /> : <ToggleLeft className="w-4 h-4 text-gray-500" />}
                {wf.enabled ? 'Enabled' : 'Disabled'}
              </button>
              <button onClick={() => handleDelete(wf.id)} className="btn-ghost text-xs text-red-400 hover:text-red-300">
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
        {workflows.length === 0 && !showCreate && (
          <div className="text-center text-gray-500 py-12">
            No workflows yet. Create one to automate actions.
          </div>
        )}
      </div>
    </div>
  )
}
