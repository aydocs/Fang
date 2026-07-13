import { useEffect, useState } from 'react'
import { bridge } from '../bridge'
import { Building2, Users, UserPlus, UserMinus, Shield, History, Trash2, X } from 'lucide-react'
import type { OrganizationRow, OrgMemberRow, AuditEntry } from '../types'

export default function Organizations() {
  const [orgs, setOrgs] = useState<OrganizationRow[]>([])
  const [selectedOrg, setSelectedOrg] = useState<string | null>(null)
  const [members, setMembers] = useState<OrgMemberRow[]>([])
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([])
  const [showCreate, setShowCreate] = useState(false)
  const [orgName, setOrgName] = useState('')
  const [orgDomain, setOrgDomain] = useState('')
  const [inviteUsername, setInviteUsername] = useState('')
  const [inviteRole, setInviteRole] = useState('member')
  const [activeTab, setActiveTab] = useState<'members' | 'audit'>('members')

  const loadOrgs = () => bridge().ListOrgs().then(setOrgs)

  useEffect(() => { loadOrgs() }, [])

  const loadMembers = async (orgID: string) => {
    bridge().ListOrgMembers(orgID).then(setMembers)
  }

  const loadAudit = async (orgID: string) => {
    try {
      const a = await bridge().GetAuditLog(orgID)
      setAuditLog(a)
    } catch {
      setAuditLog([])
    }
  }

  const selectOrg = (id: string) => {
    setSelectedOrg(id === selectedOrg ? null : id)
    if (id !== selectedOrg) {
      loadMembers(id)
      loadAudit(id)
    }
  }

  const createOrg = async () => {
    if (!orgName) return
    try {
      await bridge().CreateOrg(orgName, orgDomain)
      setOrgName('')
      setOrgDomain('')
      setShowCreate(false)
      loadOrgs()
    } catch (e: any) {
      alert('Failed: ' + e)
    }
  }

  const deleteOrg = async (id: string) => {
    if (!confirm('Delete this organization?')) return
    await bridge().DeleteOrg(id)
    if (selectedOrg === id) setSelectedOrg(null)
    loadOrgs()
  }

  const inviteUser = async () => {
    if (!inviteUsername || !selectedOrg) return
    try {
      await bridge().InviteUser(selectedOrg, inviteUsername, inviteRole)
      setInviteUsername('')
      setInviteRole('member')
      loadMembers(selectedOrg)
      loadAudit(selectedOrg)
    } catch (e: any) {
      alert('Failed: ' + e)
    }
  }

  const removeMember = async (userID: string) => {
    if (!selectedOrg || !confirm('Remove this member?')) return
    await bridge().RemoveUser(selectedOrg, userID)
    loadMembers(selectedOrg)
    loadAudit(selectedOrg)
  }

  const roleBadge = (role: string) => {
    const cls = role === 'admin' ? 'badge-critical' : role === 'member' ? 'badge-medium' : 'badge-info'
    return <span className={cls}>{role}</span>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Building2 className="w-5 h-5" />
          Organizations
        </h1>
        <button onClick={() => setShowCreate(!showCreate)} className="btn-primary flex items-center gap-2">
          <Building2 className="w-4 h-4" />
          Create Organization
        </button>
      </div>

      {showCreate && (
        <div className="card space-y-4">
          <h3 className="font-semibold">New Organization</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Name</label>
              <input className="input" value={orgName} onChange={(e) => setOrgName(e.target.value)} />
            </div>
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Domain</label>
              <input className="input" value={orgDomain} onChange={(e) => setOrgDomain(e.target.value)} placeholder="example.com" />
            </div>
          </div>
          <div className="flex gap-3">
            <button onClick={createOrg} className="btn-primary flex items-center gap-2">
              <Building2 className="w-4 h-4" />
              Create
            </button>
            <button onClick={() => setShowCreate(false)} className="btn-ghost">Cancel</button>
          </div>
        </div>
      )}

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-fang-600">
              <th className="text-left px-4 py-3 text-gray-400 font-medium">Name</th>
              <th className="text-left px-4 py-3 text-gray-400 font-medium">Domain</th>
              <th className="text-center px-4 py-3 text-gray-400 font-medium">Members</th>
              <th className="text-left px-4 py-3 text-gray-400 font-medium">Created</th>
              <th className="text-right px-4 py-3 text-gray-400 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {orgs.map((org) => (
              <tr
                key={org.ID}
                className={`border-b border-fang-600 cursor-pointer hover:bg-fang-700/50 transition-colors ${selectedOrg === org.ID ? 'bg-fang-700' : ''}`}
                onClick={() => selectOrg(org.ID)}
              >
                <td className="px-4 py-3 font-medium flex items-center gap-2">
                  <Building2 className="w-4 h-4 text-fang-300" />
                  {org.Name}
                </td>
                <td className="px-4 py-3 text-gray-400">{org.Domain || '-'}</td>
                <td className="px-4 py-3 text-center">
                  <span className="flex items-center justify-center gap-1">
                    <Users className="w-3 h-3" /> {org.MemberCount}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-400">{new Date(org.CreatedAt).toLocaleDateString()}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={(e) => { e.stopPropagation(); deleteOrg(org.ID) }}
                    className="btn-ghost text-xs"
                    title="Delete organization"
                  >
                    <Trash2 className="w-4 h-4 text-red-400" />
                  </button>
                </td>
              </tr>
            ))}
            {orgs.length === 0 && (
              <tr>
                <td colSpan={5} className="text-center py-8 text-gray-500">No organizations found.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {selectedOrg && (
        <div className="space-y-4">
          <div className="flex items-center gap-4 border-b border-fang-600 pb-2">
            <button
              onClick={() => setActiveTab('members')}
              className={`text-sm font-medium pb-2 border-b-2 transition-colors ${activeTab === 'members' ? 'border-fang-300 text-white' : 'border-transparent text-gray-400 hover:text-white'}`}
            >
              <Users className="w-4 h-4 inline mr-1" />
              Members
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              className={`text-sm font-medium pb-2 border-b-2 transition-colors ${activeTab === 'audit' ? 'border-fang-300 text-white' : 'border-transparent text-gray-400 hover:text-white'}`}
            >
              <History className="w-4 h-4 inline mr-1" />
              Audit Log
            </button>
          </div>

          {activeTab === 'members' && (
            <div className="space-y-4">
              <div className="card flex items-end gap-4">
                <div className="flex-1">
                  <label className="text-sm text-gray-400 mb-1 block">Username</label>
                  <input className="input" value={inviteUsername} onChange={(e) => setInviteUsername(e.target.value)} />
                </div>
                <div className="w-32">
                  <label className="text-sm text-gray-400 mb-1 block">Role</label>
                  <select className="input" value={inviteRole} onChange={(e) => setInviteRole(e.target.value)}>
                    <option value="admin">Admin</option>
                    <option value="member">Member</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </div>
                <button onClick={inviteUser} className="btn-primary flex items-center gap-2">
                  <UserPlus className="w-4 h-4" />
                  Invite
                </button>
              </div>

              <div className="card p-0 overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-fang-600">
                      <th className="text-left px-4 py-3 text-gray-400 font-medium">Username</th>
                      <th className="text-left px-4 py-3 text-gray-400 font-medium">Role</th>
                      <th className="text-left px-4 py-3 text-gray-400 font-medium">Joined</th>
                      <th className="text-right px-4 py-3 text-gray-400 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.map((m) => (
                      <tr key={m.ID} className="border-b border-fang-600">
                        <td className="px-4 py-3 flex items-center gap-2">
                          <Shield className="w-4 h-4 text-fang-300" />
                          {m.Username}
                        </td>
                        <td className="px-4 py-3">{roleBadge(m.Role)}</td>
                        <td className="px-4 py-3 text-gray-400">{new Date(m.JoinedAt).toLocaleDateString()}</td>
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={() => removeMember(m.UserID)}
                            className="btn-ghost text-xs"
                            title="Remove member"
                          >
                            <UserMinus className="w-4 h-4 text-red-400" />
                          </button>
                        </td>
                      </tr>
                    ))}
                    {members.length === 0 && (
                      <tr>
                        <td colSpan={4} className="text-center py-8 text-gray-500">No members.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'audit' && (
            <div className="card p-0 overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-fang-600">
                    <th className="text-left px-4 py-3 text-gray-400 font-medium">User</th>
                    <th className="text-left px-4 py-3 text-gray-400 font-medium">Action</th>
                    <th className="text-left px-4 py-3 text-gray-400 font-medium">Resource</th>
                    <th className="text-left px-4 py-3 text-gray-400 font-medium">Details</th>
                    <th className="text-left px-4 py-3 text-gray-400 font-medium">Date</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLog.map((entry) => (
                    <tr key={entry.ID} className="border-b border-fang-600">
                      <td className="px-4 py-3">{entry.Username || entry.UserID}</td>
                      <td className="px-4 py-3">{entry.Action}</td>
                      <td className="px-4 py-3 text-gray-400">{entry.Resource}</td>
                      <td className="px-4 py-3 text-gray-400">{entry.Details}</td>
                      <td className="px-4 py-3 text-gray-400">{new Date(entry.CreatedAt).toLocaleString()}</td>
                    </tr>
                  ))}
                  {auditLog.length === 0 && (
                    <tr>
                      <td colSpan={5} className="text-center py-8 text-gray-500">No audit entries.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
